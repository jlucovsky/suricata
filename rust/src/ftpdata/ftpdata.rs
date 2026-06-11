/* Copyright (C) 2026 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

//! FTP-DATA app-layer state machine.  Ports the C FTPDataParse* functions
//! from app-layer-ftp.c.  One state per flow; the state doubles as the
//! single transaction (FTPDataGetTx returns the state itself).

use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

use crate::applayer::{
    AppLayerRegisterParser, AppLayerResult, AppLayerResultRust, AppLayerStateData, AppLayerTxData,
    StreamSliceRust, APP_LAYER_PARSER_EOF_TC, APP_LAYER_PARSER_EOF_TS,
    APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
};
use crate::core::{IPPROTO_TCP, STREAM_TOCLIENT, STREAM_TOSERVER};
use crate::ftp::constant::{FtpDataStateValues, FtpRequestCommand};
use crate::ftp::ftp::FtpTransferCmd;
use suricata_sys::sys::{
    AppLayerGetFileState, AppLayerParserState, AppProto,
    FileAppendData, FileCloseFileById, FileOpenFileWithId,
    SCAppLayerParserRegisterParserAcceptableDataDirection,
    SCAppLayerParserStateIssetFlag, SCAppLayerParserRegisterLogger,
    SCFileFlowFlagsToFlags, StreamingBufferConfig, StreamSlice,
    FileContainer, Flow,
};
#[cfg(not(test))]
use suricata_sys::sys::FileContainerRecycle;

extern "C" {
    /// Returns the `FtpTransferCmd` stored in flow expectation storage, or
    /// NULL if none.  Does not transfer ownership; call
    /// `SCFTPDataFlowFreeTransferCmd` when done.
    fn SCFTPDataFlowGetTransferCmd(f: *const Flow) -> *const FtpTransferCmd;
    /// Frees the expectation storage entry for this flow.
    fn SCFTPDataFlowFreeTransferCmd(f: *mut Flow);
    /// Sets `f->parent_id`.
    fn SCFTPDataFlowSetParentId(f: *mut Flow, parent_id: u64);
    /// Returns a pointer to the static `StreamingBufferConfig` used for
    /// FTP-DATA file operations (configured with the FTP memcap allocators).
    pub fn SCFTPDataGetSbcfg() -> *const StreamingBufferConfig;
}

const FTPDATA_FINISHED: u8 = FtpDataStateValues::FTPDATA_STATE_FINISHED as u8;
const FTPDATA_IN_PROGRESS: u8 = FtpDataStateValues::FTPDATA_STATE_IN_PROGRESS as u8;

/// FTP-DATA app-layer state.  Also serves as the sole transaction.
pub struct FtpDataState {
    pub files: FileContainer,
    pub file_name: Vec<u8>,
    pub tx_data: AppLayerTxData,
    pub state_data: AppLayerStateData,
    pub command: FtpRequestCommand,
    /// Direction the file data flows (STREAM_TOSERVER or STREAM_TOCLIENT).
    pub direction: u8,
    pub progress: u8,
    /// True once the file has been opened via FileOpenFileWithId.
    files_opened: bool,
}

impl FtpDataState {
    pub fn new() -> Self {
        FtpDataState {
            files: FileContainer::default(),
            file_name: Vec::new(),
            tx_data: AppLayerTxData::new(),
            state_data: AppLayerStateData::default(),
            command: FtpRequestCommand::FTP_COMMAND_UNKNOWN,
            direction: 0,
            progress: FTPDATA_IN_PROGRESS,
            files_opened: false,
        }
    }

    unsafe fn parse(
        &mut self, flow: *mut Flow, pstate: *mut AppLayerParserState, input: &[u8], direction: u8,
    ) -> AppLayerResult {
        let sbcfg = SCFTPDataGetSbcfg();

        let eof = if direction & STREAM_TOSERVER != 0 {
            SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) != 0
        } else {
            SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) != 0
        };

        self.tx_data.update_file_flags(self.state_data.file_flags);
        if self.tx_data.0.file_tx == 0 {
            self.tx_data.0.file_tx = direction & (STREAM_TOSERVER | STREAM_TOCLIENT);
        }
        if direction & STREAM_TOSERVER != 0 {
            self.tx_data.0.updated_ts = true;
        } else {
            self.tx_data.0.updated_tc = true;
        }

        let flags = SCFileFlowFlagsToFlags(self.tx_data.0.file_flags, direction);
        let mut ret: c_int = 0;

        if !input.is_empty() && !self.files_opened {
            // First data: retrieve transfer info from flow expectation storage.
            let data = SCFTPDataFlowGetTransferCmd(flow);
            if data.is_null() {
                return AppLayerResult::err();
            }

            // Read all fields from the expectation before freeing it.
            // Matches upstream C: always consume the expectation on the first
            // non-empty packet, even if the direction doesn't match yet.
            if !(*data).file_name.is_null() {
                let len = (*data).file_len as usize;
                self.file_name =
                    std::slice::from_raw_parts((*data).file_name, len).to_vec();
            }
            self.direction = (*data).direction;
            self.command = match (*data).cmd {
                x if x == FtpRequestCommand::FTP_COMMAND_STOR as u8 => {
                    FtpRequestCommand::FTP_COMMAND_STOR
                }
                x if x == FtpRequestCommand::FTP_COMMAND_RETR as u8 => {
                    FtpRequestCommand::FTP_COMMAND_RETR
                }
                _ => FtpRequestCommand::FTP_COMMAND_UNKNOWN,
            };
            SCFTPDataFlowSetParentId(flow, (*data).flow_id);
            SCFTPDataFlowFreeTransferCmd(flow);
            self.initialized = true;

            // Data in wrong direction: metadata cached, no file to open yet.
            if direction & self.direction == 0 {
                return AppLayerResult::ok();
            }

            if !self.file_name.is_empty() {
                ret = FileOpenFileWithId(
                    &mut self.files,
                    sbcfg,
                    0,
                    self.file_name.as_ptr(),
                    u16::try_from(self.file_name.len()).unwrap_or(u16::MAX),
                    input.as_ptr(),
                    u32::try_from(input.len()).unwrap_or(u32::MAX),
                    flags,
                );
                if ret == 0 {
                    self.files_opened = true;
                    self.tx_data.0.files_opened = 1;
                }
            }
        } else {
            // Subsequent data (or empty first call).
            if direction & self.direction == 0 {
                return AppLayerResult::ok();
            }
            if self.progress == FTPDATA_FINISHED {
                return AppLayerResult::ok();
            }
            if !input.is_empty() {
                ret = FileAppendData(
                    &mut self.files, sbcfg, input.as_ptr(),
                    u32::try_from(input.len()).unwrap_or(u32::MAX),
                );
                if ret == -2 {
                    // File no longer being extracted; not a parser error.
                    return AppLayerResult::ok();
                }
            }
        }

        if self.files_opened && eof {
            ret = FileCloseFileById(&mut self.files, sbcfg, 0, ptr::null(), 0, flags);
            self.progress = FTPDATA_FINISHED;
        }

        if ret < 0 {
            AppLayerResult::err()
        } else {
            AppLayerResult::ok()
        }
    }
}

impl Drop for FtpDataState {
    fn drop(&mut self) {
        #[cfg(not(test))]
        unsafe {
            let sbcfg = SCFTPDataGetSbcfg();
            if !sbcfg.is_null() {
                FileContainerRecycle(&mut self.files, sbcfg);
            }
        }
    }
}

// ─── C-callable exports ───────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn SCFTPDataStateNew(
    _orig_state: *mut c_void, _orig_proto: AppProto,
) -> *mut c_void {
    Box::into_raw(Box::new(FtpDataState::new())) as *mut c_void
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPDataStateFree(state: *mut c_void) {
    if !state.is_null() {
        drop(Box::from_raw(state as *mut FtpDataState));
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPDataStateTransactionFree(_state: *mut c_void, _tx_id: u64) {
    // Single-tx protocol; nothing to do.
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPDataParseRequest(
    flow: *mut Flow, state: *mut c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _local_data: *mut c_void,
) -> AppLayerResult {
    let state = &mut *(state as *mut FtpDataState);
    let input = if stream_slice.is_gap() {
        &[][..]
    } else {
        stream_slice.as_slice()
    };
    state.parse(flow, pstate, input, STREAM_TOSERVER)
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPDataParseResponse(
    flow: *mut Flow, state: *mut c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _local_data: *mut c_void,
) -> AppLayerResult {
    let state = &mut *(state as *mut FtpDataState);
    let input = if stream_slice.is_gap() {
        &[][..]
    } else {
        stream_slice.as_slice()
    };
    state.parse(flow, pstate, input, STREAM_TOCLIENT)
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPDataGetTx(state: *mut c_void, _tx_id: u64) -> *mut c_void {
    // The state is the single transaction.
    state
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPDataGetTxCnt(_state: *mut c_void) -> u64 {
    1
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPDataGetAlstateProgress(tx: *mut c_void, direction: u8) -> c_int {
    let state = &*(tx as *const FtpDataState);
    if !state.initialized || direction == state.direction {
        state.progress as c_int
    } else {
        FTPDATA_FINISHED as c_int
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPDataGetTxFiles(
    tx: *mut c_void, direction: u8,
) -> AppLayerGetFileState {
    let state = &mut *(tx as *mut FtpDataState);
    if direction == state.direction {
        AppLayerGetFileState {
            fc: &mut state.files,
            cfg: SCFTPDataGetSbcfg(),
        }
    } else {
        AppLayerGetFileState::default()
    }
}

/// Returns the raw `FtpRequestCommand` value for use by detect-ftpdata.c.
#[no_mangle]
pub unsafe extern "C" fn SCFTPDataGetCommandValue(state: *const c_void) -> u8 {
    let state = &*(state as *const FtpDataState);
    state.command as u8
}

export_tx_data_get!(ftpdata_get_tx_data, FtpDataState);
export_state_data_get!(ftpdata_get_state_data, FtpDataState);

// ─── Parser registration ──────────────────────────────────────────────────────

const PARSER_NAME: &[u8] = b"ftp-data\0";

/// Registers the FTP-DATA Rust parser.  Called from C `RegisterFTPParsers`
/// after `ALPROTO_FTPDATA` is assigned and `AppLayerRegisterExpectationProto`
/// is called.
#[no_mangle]
pub unsafe extern "C" fn SCFTPDataRegisterParsers(alproto: AppProto) {
    use crate::applayer::RustParser;

    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: ptr::null(),
        ipproto: IPPROTO_TCP,
        probe_ts: None,
        probe_tc: None,
        min_depth: 0,
        max_depth: 0,
        state_new: SCFTPDataStateNew,
        state_free: SCFTPDataStateFree,
        tx_free: SCFTPDataStateTransactionFree,
        parse_ts: SCFTPDataParseRequest,
        parse_tc: SCFTPDataParseResponse,
        get_tx_count: SCFTPDataGetTxCnt,
        get_tx: SCFTPDataGetTx,
        tx_comp_st_ts: FTPDATA_FINISHED as c_int,
        tx_comp_st_tc: FTPDATA_FINISHED as c_int,
        tx_get_progress: SCFTPDataGetAlstateProgress,
        get_eventinfo: None,
        get_eventinfo_byid: None,
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: Some(SCFTPDataGetTxFiles),
        get_tx_iterator: None,
        get_tx_data: ftpdata_get_tx_data,
        get_state_data: ftpdata_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
        get_state_id_by_name: None,
        get_state_name_by_id: None,
    };

    AppLayerRegisterParser(&parser, alproto);
    SCAppLayerParserRegisterLogger(IPPROTO_TCP, alproto);
    SCAppLayerParserRegisterParserAcceptableDataDirection(
        IPPROTO_TCP,
        alproto,
        STREAM_TOSERVER | STREAM_TOCLIENT,
    );
}
