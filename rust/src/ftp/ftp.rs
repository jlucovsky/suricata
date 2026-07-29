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

//! FTP application layer state machine, transaction management, and parser registration.

use std::collections::VecDeque;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

use crate::applayer::{
    AppLayerResult, AppLayerResultRust, AppLayerStateData, AppLayerTxData,
    State, StreamSliceRust, Transaction,
    APP_LAYER_PARSER_EOF_TC, APP_LAYER_PARSER_EOF_TS, APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
};
use crate::conf::{conf_get, get_memval};
use crate::core::{ALPROTO_FAILED, ALPROTO_UNKNOWN, IPPROTO_TCP, STREAM_TOCLIENT, STREAM_TOSERVER};
use crate::direction::Direction;
use crate::flow::{flow_get_alproto_tc, flow_get_alproto_ts, flow_get_todst_bytecount, Flow};
use crate::ftp::constant::*;
use crate::ftp::event::FtpEvent;
use crate::ftp::memcap::ftp_check_memcap;
use crate::ftp::parser::{
    extract_line, is_preliminary_response, parse_eprt_from_line, parse_epsv_port,
    parse_pasv_port, parse_port_from_line, parse_request_line, parse_response_line,
    FtpResponseLine,
};
use suricata_sys::sys::{
    AppLayerGetTxIterState, AppLayerGetTxIterTuple, AppLayerParserState, AppProto, AppProtoEnum,
    SCAppLayerParserConfParserEnabled, SCAppLayerParserRegisterLogger,
    SCAppLayerParserRegisterParserAcceptableDataDirection, SCAppLayerParserStateIssetFlag,
    SCAppLayerProtoDetectConfProtoDetectionEnabled, SCAppLayerProtoDetectPMRegisterPatternCI,
    SCAppLayerProtoDetectPMRegisterPatternCSwPP, SCAppLayerProtoDetectPPParseConfPorts,
    SCAppLayerProtoDetectPPRegister, SCAppLayerRequestProtocolTLSUpgrade,
};

#[repr(C)]
pub struct DetectFtpModeData {
    pub active: bool,
}

#[repr(C)]
pub struct DetectFtpReplyReceivedData {
    pub received: bool,
}


#[repr(C)]
pub struct FtpTransferCmd {
    // Must be first -- required by app-layer expectation logic.
    data_free: unsafe extern "C" fn(*mut c_void),
    pub flow_id: u64,
    pub file_name: *mut u8,
    pub file_len: u16,
    pub direction: u8,
    pub cmd: u8,
}

impl Default for FtpTransferCmd {
    fn default() -> Self {
        FtpTransferCmd {
            flow_id: 0,
            file_name: std::ptr::null_mut(),
            file_len: 0,
            direction: 0,
            cmd: 0,
            data_free: default_free_fn,
        }
    }
}

unsafe extern "C" fn default_free_fn(_ptr: *mut c_void) {}


#[no_mangle]
pub unsafe extern "C" fn SCFTPGetConfigValues(
    memcap: *mut u64, max_tx: *mut u32, max_line_len: *mut u32,
) {
    if let Some(val) = conf_get("app-layer.protocols.ftp.memcap") {
        if let Ok(v) = get_memval(val) {
            *memcap = v;
            SCLogConfig!("FTP memcap: {}", v);
        } else {
            SCLogWarning!(
                "Invalid value {} for ftp.memcap; defaulting to {}",
                val,
                *memcap
            );
        }
    }
    if let Some(val) = conf_get("app-layer.protocols.ftp.max-tx") {
        if let Ok(v) = val.parse::<u32>() {
            *max_tx = v;
            SCLogConfig!("FTP max tx: {}", v);
        } else {
            SCLogWarning!(
                "Invalid value {} for ftp.max-tx; defaulting to {}",
                val,
                *max_tx
            );
        }
    }
    if let Some(val) = conf_get("app-layer.protocols.ftp.max-line-length") {
        if let Ok(v) = get_memval(val) {
            *max_line_len = v as u32;
            SCLogConfig!("FTP max line length: {}", v);
        } else {
            SCLogWarning!(
                "Invalid value {} for ftp.max-line-length; defaulting to {}",
                val,
                *max_line_len
            );
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPParseReplyReceived(
    c_str: *const c_char,
) -> *mut DetectFtpReplyReceivedData {
    if c_str.is_null() {
        return ptr::null_mut();
    }
    let Ok(input_str) = CStr::from_ptr(c_str).to_str() else {
        return ptr::null_mut();
    };
    let trimmed = input_str.trim();
    let received_val = match trimmed {
        s if s.eq_ignore_ascii_case("true") || s.eq_ignore_ascii_case("1")
            || s.eq_ignore_ascii_case("yes") || s.eq_ignore_ascii_case("on") => true,
        s if s.eq_ignore_ascii_case("false") || s.eq_ignore_ascii_case("0")
            || s.eq_ignore_ascii_case("no") || s.eq_ignore_ascii_case("off") => false,
        _ => return ptr::null_mut(),
    };
    let boxed = Box::new(DetectFtpReplyReceivedData {
        received: received_val,
    });
    Box::into_raw(boxed)
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPFreeReplyReceivedData(ptr: *mut DetectFtpReplyReceivedData) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPParseMode(c_str: *const c_char) -> *mut DetectFtpModeData {
    if c_str.is_null() {
        return ptr::null_mut();
    }
    let Ok(input_str) = CStr::from_ptr(c_str).to_str() else {
        return ptr::null_mut();
    };
    let trimmed = input_str.trim();
    let is_active = if trimmed.eq_ignore_ascii_case("active") {
        true
    } else if trimmed.eq_ignore_ascii_case("passive") {
        false
    } else {
        return ptr::null_mut();
    };
    let boxed = Box::new(DetectFtpModeData { active: is_active });
    Box::into_raw(boxed)
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPFreeModeData(ptr: *mut DetectFtpModeData) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
    }
}

/// Returns *mut FtpTransferCmd
#[no_mangle]
pub unsafe extern "C" fn SCFTPTransferCmdNew() -> *mut FtpTransferCmd {
    SCLogDebug!("allocating ftp transfer cmd");
    let cmd = FtpTransferCmd::default();
    Box::into_raw(Box::new(cmd))
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPTransferCmdFree(cmd: *mut FtpTransferCmd) {
    SCLogDebug!("freeing ftp transfer cmd");
    if !cmd.is_null() {
        let _transfer_cmd = Box::from_raw(cmd);
    }
}

// ─── AppProto static ──────────────────────────────────────────────────────────

pub(super) static mut ALPROTO_FTP: AppProto = ALPROTO_UNKNOWN;

// ─── Config ───────────────────────────────────────────────────────────────────

pub struct FtpConfig {
    pub max_tx: u32,
    pub max_line_len: u32,
    pub memcap: u64,
}

impl Default for FtpConfig {
    fn default() -> Self {
        FtpConfig {
            max_tx: 1024,
            max_line_len: 4096,
            memcap: 0,
        }
    }
}

impl FtpConfig {
    /// Load config from the Suricata C configuration.  In test builds this
    /// returns the defaults so that no C runtime is required.
    pub fn load() -> Self {
        #[cfg(not(test))]
        {
            let mut cfg = FtpConfig::default();
            unsafe {
                SCFTPGetConfigValues(&mut cfg.memcap, &mut cfg.max_tx, &mut cfg.max_line_len);
            }
            cfg
        }
        #[cfg(test)]
        FtpConfig::default()
    }
}

// ─── FTP-DATA expectation ─────────────────────────────────────────────────────

/// Expectation queued by parse_request (STOR/RETR) and created in
/// SCFTPParseRequest once we have the Flow pointer.
struct PendingExpectation {
    file_name: Vec<u8>,
    cmd: u8,
    direction: u8,
    dyn_port: u16,
}

extern "C" {
    /// Bridge to C: allocates FtpTransferCmd via FTPCalloc, sets flow_id via
    /// FlowGetId, then calls AppLayerExpectationCreate.  Ownership of the
    /// allocation is transferred to the expectation engine on success.
    fn SCFTPDataExpectCreate(
        f: *mut Flow,
        file_name: *const u8,
        file_name_len: u32,
        cmd: u8,
        direction: u8,
        dyn_port: u16,
    ) -> bool;
}

// ─── Transaction ─────────────────────────────────────────────────────────────

const MAX_RESPONSE_LINES: usize = 512;

pub struct FtpTransaction {
    pub tx_id: u64,
    /// Full request line (without \r\n).
    pub request: Option<Vec<u8>>,
    pub request_truncated: bool,
    pub command: FtpRequestCommand,
    /// Raw command name bytes.
    pub command_name: Vec<u8>,
    /// Byte offset into `request` where the argument starts (past cmd + space).
    pub arg_offset: usize,
    pub dyn_port: u16,
    /// true = active (PORT/EPRT), false = passive (PASV/EPSV).
    pub active: bool,
    /// All response lines for this command.
    pub responses: Vec<FtpResponseLine>,
    pub reply_truncated: bool,
    /// Transaction is complete (final non-preliminary reply received).
    pub complete: bool,
    pub tx_data: AppLayerTxData,
}

impl FtpTransaction {
    pub fn new(tx_id: u64) -> Self {
        FtpTransaction {
            tx_id,
            request: None,
            request_truncated: false,
            command: FtpRequestCommand::FTP_COMMAND_UNKNOWN,
            command_name: Vec::new(),
            arg_offset: 0,
            dyn_port: 0,
            active: false,
            responses: Vec::new(),
            reply_truncated: false,
            complete: false,
            // Use Default (all zeros) rather than AppLayerTxData::new(),
            // which pre-sets updated_tc and updated_ts to true.  parse_request
            // sets updated_ts on tx creation; parse_response sets updated_tc.
            // Pre-setting both would cause detection to run TC-side engines
            // on TS-only packets and fire spurious early alerts.
            tx_data: AppLayerTxData(Default::default()),
        }
    }
}

impl Transaction for FtpTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

// ─── State ────────────────────────────────────────────────────────────────────

/// AUTH TLS handshake state.  The client sends `AUTH TLS`, the server
/// replies `234`, and only then does the flow upgrade to TLS.  These
/// stages don't correspond to any transaction, so they're tracked here.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum AuthTlsState {
    /// No AUTH TLS handshake in progress.
    Idle,
    /// Client sent `AUTH TLS`; awaiting server response.
    Requested,
    /// Server sent `234`; parse_response should trigger TLS upgrade
    /// once the Flow pointer is available.
    Confirmed,
}

pub struct FtpState {
    pub state_data: AppLayerStateData,
    pub transactions: VecDeque<FtpTransaction>,
    tx_cnt: u64,
    request_buf: Vec<u8>,
    response_buf: Vec<u8>,
    request_gap: bool,
    response_gap: bool,
    pub config: FtpConfig,
    /// Dynamic port from the most-recent confirmed PORT/EPRT/PASV/EPSV exchange.
    /// Reset to 0 when consumed by a STOR/RETR expectation.
    curr_dyn_port: u16,
    curr_active: bool,
    /// Expectations queued during parse_request; created in SCFTPParseRequest
    /// where the Flow pointer is available.
    pending_expectations: Vec<PendingExpectation>,
    /// AUTH TLS handshake state.  AUTH TLS does not create a transaction, so
    /// the multi-step upgrade must be tracked at state level.
    auth_tls: AuthTlsState,
    /// Set while accumulating a multi-line response (code seen with '-' separator).
    /// Cleared when the matching final line (same code, ' ' separator) arrives.
    response_multiline_code: Option<u16>,
}

/// Cap `buf` at `max_len` when there is no newline, so that when `\n`
/// eventually arrives, `extract_line` sees exactly `max_len` bytes and
/// reports the line as truncated.
fn cap_linebuf(buf: &mut Vec<u8>, max_len: usize) {
    if buf.len() > max_len && !buf.contains(&b'\n') {
        buf.truncate(max_len);
    }
}

impl State<FtpTransaction> for FtpState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&FtpTransaction> {
        self.transactions.get(index)
    }
}

impl FtpState {
    pub fn new() -> Self {
        FtpState {
            state_data: AppLayerStateData::default(),
            transactions: VecDeque::new(),
            tx_cnt: 0,
            request_buf: Vec::new(),
            response_buf: Vec::new(),
            request_gap: false,
            response_gap: false,
            config: FtpConfig::default(),
            curr_dyn_port: 0,
            curr_active: false,
            pending_expectations: Vec::new(),
            auth_tls: AuthTlsState::Idle,
            response_multiline_code: None,
        }
    }

    pub fn get_transaction(&self, tx_id: u64) -> Option<&FtpTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    pub fn get_transaction_mut(&mut self, tx_id: u64) -> Option<&mut FtpTransaction> {
        self.transactions
            .iter_mut()
            .find(|tx| tx.tx_id == tx_id + 1)
    }

    fn free_tx(&mut self, tx_id: u64) {
        if let Some(index) = self
            .transactions
            .iter()
            .position(|tx| tx.tx_id == tx_id + 1)
        {
            self.transactions.remove(index);
        }
    }

    /// Create a new transaction.  When at the max-tx limit, mark the oldest
    /// incomplete transaction done + tag it with the too_many_transactions
    /// event, and return None: refusing to grow the transaction list under
    /// pressure avoids quadratic behaviour on bursty inputs.  Once the
    /// upper layer frees completed transactions, len() drops and creation
    /// resumes.
    fn new_tx(&mut self) -> Option<u64> {
        if self.transactions.len() >= self.config.max_tx as usize {
            if let Some(tx) = self.transactions.iter_mut().find(|tx| !tx.complete) {
                tx.complete = true;
                tx.tx_data.0.updated_ts = true;
                tx.tx_data.0.updated_tc = true;
                tx.tx_data.set_event(FtpEvent::FtpEventTooManyTransactions as u8);
            }
            return None;
        }

        self.tx_cnt += 1;
        let tx_id = self.tx_cnt;
        self.transactions.push_back(FtpTransaction::new(tx_id));
        Some(tx_id)
    }

    /// Return the oldest incomplete (not-yet-done) transaction, or the oldest
    /// transaction if all are complete.  Mirrors FTPGetOldestTx.
    fn get_oldest_tx_mut(&mut self) -> Option<&mut FtpTransaction> {
        // First pass: find oldest incomplete.
        let pos = self
            .transactions
            .iter()
            .position(|tx| !tx.complete);
        if let Some(p) = pos {
            return self.transactions.get_mut(p);
        }
        // All complete: return last.
        let last = self.transactions.len().checked_sub(1)?;
        self.transactions.get_mut(last)
    }

    pub fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        self.request_gap = false;
        self.request_buf.extend_from_slice(input);
        let max_len = self.config.max_line_len as usize;
        cap_linebuf(&mut self.request_buf, max_len);

        loop {
            match extract_line(&self.request_buf, max_len) {
                None => {
                    // No complete line yet.
                    break;
                }
                Some((line, consumed, truncated)) => {
                    self.request_buf.drain(..consumed);

                    if line.is_empty() {
                        continue;
                    }

                    // Strip leading Telnet OOB bytes (e.g. IAC IP IAC DM preceding
                    // in-band ABOR) so the command parser sees the ASCII command token.
                    let skip = line.iter().position(|&b| b.is_ascii_alphabetic()).unwrap_or(line.len());
                    let line = if skip > 0 { line[skip..].to_vec() } else { line };
                    if line.is_empty() {
                        continue;
                    }

                    let (command, command_name, arg_offset) = match parse_request_line(&line) {
                        Ok((_, req)) => {
                            let name = req.command_name.to_vec();
                            let offset = if req.arg.is_some() {
                                name.len() + 1 // cmd + space
                            } else {
                                name.len()
                            };
                            (req.command, name, offset)
                        }
                        Err(_) => {
                            continue;
                        }
                    };

                    // AUTH TLS does not create a transaction: track the upgrade
                    // signal at state level so parse_response can detect 234.
                    if matches!(command, FtpRequestCommand::FTP_COMMAND_AUTH_TLS) {
                        self.auth_tls = AuthTlsState::Requested;
                        continue;
                    }
                    // Unknown commands don't produce events; skip transaction creation
                    // so they don't displace subsequent named-command responses.
                    if matches!(command, FtpRequestCommand::FTP_COMMAND_UNKNOWN) {
                        continue;
                    }

                    // Create transaction; accessed via back_mut() below.
                    // Skip the request line if we're at the tx cap: the
                    // too_many_transactions event has already been attached
                    // to the reaped oldest tx.
                    if self.new_tx().is_none() {
                        continue;
                    }

                    {
                        let tx = self.transactions.back_mut().unwrap();

                        tx.tx_data.0.updated_ts = true;
                        tx.command = command;
                        tx.command_name = command_name;
                        tx.arg_offset = arg_offset;
                        tx.request = Some(line.clone());
                        tx.request_truncated = truncated;

                        if truncated {
                            tx.tx_data
                                .set_event(FtpEvent::FtpEventRequestCommandTooLong as u8);
                        }

                        // Parse PORT/EPRT argument for active mode.  Store in the
                        // transaction for logging; curr_dyn_port is set at response
                        // time (matching the C implementation) so that a rejected
                        // PORT does not prime the expectation for a subsequent STOR.
                        match command {
                            FtpRequestCommand::FTP_COMMAND_PORT => {
                                let port = parse_port_from_line(&line);
                                if port != 0 {
                                    tx.dyn_port = port;
                                    tx.active = true;
                                }
                            }
                            FtpRequestCommand::FTP_COMMAND_EPRT => {
                                let port = parse_eprt_from_line(&line);
                                if port != 0 {
                                    tx.dyn_port = port;
                                    tx.active = true;
                                }
                            }
                            FtpRequestCommand::FTP_COMMAND_PASV
                            | FtpRequestCommand::FTP_COMMAND_EPSV => {
                                tx.active = false;
                            }
                            _ => {}
                        }
                    }

                    // STOR/RETR need a file name; NLST does not.  All three
                    // need a negotiated dynamic port.  Emit file_before_port
                    // / file_without_name events on the tx instead of erroring,
                    // matching the C behaviour.
                    let requires_file = matches!(
                        command,
                        FtpRequestCommand::FTP_COMMAND_STOR
                            | FtpRequestCommand::FTP_COMMAND_APPE
                            | FtpRequestCommand::FTP_COMMAND_RETR
                    );
                    // STOU may or may not carry a filename; NLST/LIST/MLSD
                    // never do.
                    let is_data_cmd = requires_file
                        || matches!(
                            command,
                            FtpRequestCommand::FTP_COMMAND_NLST
                                | FtpRequestCommand::FTP_COMMAND_LIST
                                | FtpRequestCommand::FTP_COMMAND_MLSD
                                | FtpRequestCommand::FTP_COMMAND_STOU
                        );
                    if is_data_cmd {
                        if requires_file && arg_offset >= line.len() {
                            let tx = self.transactions.back_mut().unwrap();
                            tx.tx_data
                                .set_event(FtpEvent::FtpEventFileWithoutName as u8);
                        } else if self.curr_dyn_port == 0 {
                            let tx = self.transactions.back_mut().unwrap();
                            tx.tx_data.set_event(FtpEvent::FtpEventFileBeforePort as u8);
                        } else {
                            // Mirror the direction logic from the C FTPParseRequest:
                            // active+STOR or passive+(RETR|NLST) => TOCLIENT; else TOSERVER.
                            // Server-to-client for STOR in active mode, and
                            // for any of RETR/NLST/LIST/MLSD in passive mode.
                            let server_to_client = matches!(
                                command,
                                FtpRequestCommand::FTP_COMMAND_RETR
                                    | FtpRequestCommand::FTP_COMMAND_NLST
                                    | FtpRequestCommand::FTP_COMMAND_LIST
                                    | FtpRequestCommand::FTP_COMMAND_MLSD
                            );
                            // STOR/APPE/STOU in active mode: server initiates
                            // the data connection, so the upload flows
                            // TOCLIENT from the FTP-DATA flow's perspective.
                            let active_upload = matches!(
                                command,
                                FtpRequestCommand::FTP_COMMAND_STOR
                                    | FtpRequestCommand::FTP_COMMAND_APPE
                                    | FtpRequestCommand::FTP_COMMAND_STOU
                            );
                            let direction = if (self.curr_active && active_upload)
                                || (!self.curr_active && server_to_client)
                            {
                                STREAM_TOCLIENT
                            } else {
                                STREAM_TOSERVER
                            };
                            let file_name = if arg_offset < line.len() {
                                line[arg_offset..].to_vec()
                            } else if command == FtpRequestCommand::FTP_COMMAND_STOU {
                                // STOU without a client-provided filename:
                                // the server picks one, but we need a
                                // placeholder for file storage / detection.
                                b"<stou>".to_vec()
                            } else {
                                Vec::new()
                            };
                            self.pending_expectations.push(PendingExpectation {
                                file_name,
                                cmd: command as u8,
                                direction,
                                dyn_port: self.curr_dyn_port,
                            });
                            self.curr_dyn_port = 0;
                            self.curr_active = false;
                        }
                    }
                }
            }
        }

        AppLayerResult::ok()
    }

    pub fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        self.response_gap = false;
        self.response_buf.extend_from_slice(input);
        let max_len = self.config.max_line_len as usize;
        cap_linebuf(&mut self.response_buf, max_len);

        loop {
            match extract_line(&self.response_buf, max_len) {
                None => break,
                Some((line, consumed, truncated)) => {
                    self.response_buf.drain(..consumed);

                    if line.is_empty() {
                        continue;
                    }

                    // Parse the response line.  For lines that don't start with
                    // a 3-digit code (intermediate lines in a multi-line response),
                    // treat them as continuation lines when a multi-line response is
                    // active, storing the raw line as the message.
                    let (code, is_continuation, is_preliminary, resp) =
                        match parse_response_line(&line) {
                            Ok((_, mut r)) => {
                                if r.is_continuation {
                                    self.response_multiline_code = Some(r.code);
                                    // Store the full raw line so the logger outputs
                                    // "NNN-text" rather than just "text", matching the
                                    // reference C implementation.
                                    r.message = line.to_vec();
                                } else {
                                    self.response_multiline_code = None;
                                }
                                let code = r.code;
                                let cont = r.is_continuation;
                                let prelim = is_preliminary_response(code);
                                (code, cont, prelim, r)
                            }
                            Err(_) => {
                                // Not a valid response line.
                                if let Some(pending_code) = self.response_multiline_code {
                                    // Inside a multi-line response: accumulate as continuation.
                                    let r = FtpResponseLine {
                                        code: pending_code,
                                        is_continuation: true,
                                        message: line.to_vec(),
                                        code_str: [b'0', b'0', b'0'],
                                    };
                                    let prelim = is_preliminary_response(pending_code);
                                    (pending_code, true, prelim, r)
                                } else {
                                    // Non-standard response with no 3-digit code (e.g. some
                                    // servers send "UNIX Type: L8" for SYST).  Synthesize a
                                    // code-0 completion so the oldest incomplete transaction
                                    // advances and subsequent well-formed responses land in
                                    // the right slots.
                                    let r = FtpResponseLine {
                                        code: 0,
                                        is_continuation: false,
                                        message: line.to_vec(),
                                        code_str: [b'0', b'0', b'0'],
                                    };
                                    (0, false, false, r)
                                }
                            }
                        };

                    // AUTH TLS 234 upgrade: detected via state field because
                    // AUTH TLS does not create a transaction.
                    if self.auth_tls == AuthTlsState::Requested {
                        if code == 234 {
                            self.auth_tls = AuthTlsState::Confirmed;
                        } else {
                            self.auth_tls = AuthTlsState::Idle;
                        }
                    }

                    // None only when deque is empty (banner before any command).
                    // If new_tx also fails (at max-tx), drop the response line;
                    // there is no tx to attach it to.
                    let (tx_id, tx_is_response_only) =
                        if let Some(tx) = self.get_oldest_tx_mut() {
                            (tx.tx_id, false)
                        } else if let Some(id) = self.new_tx() {
                            (id, true)
                        } else {
                            continue;
                        };

                    // Locals to carry state updates past the tx borrow.
                    let mut new_active_port: u16 = 0;
                    let mut new_passive_port: u16 = 0;

                    // Now get a mutable borrow to work with.
                    let tx = self
                        .transactions
                        .iter_mut()
                        .find(|tx| tx.tx_id == tx_id)
                        .unwrap();

                    if tx_is_response_only {
                        // No corresponding request (e.g. the initial banner):
                        // this is a TC-only tx.  for_direction(ToClient) sets
                        // updated_tc=true and SKIP_INSPECT_TS in one go, so
                        // firewall-mode rules aren't stuck waiting for a
                        // request that will never come.
                        tx.tx_data = AppLayerTxData::for_direction(Direction::ToClient);
                    } else {
                        tx.tx_data.0.updated_tc = true;
                    }
                    // reply_received is derived from tx.complete at match /
                    // log time (matching upstream tx->done semantics);
                    // truncated is a separate independent signal.
                    if truncated {
                        tx.reply_truncated = true;
                        tx.tx_data
                            .set_event(FtpEvent::FtpEventResponseCommandTooLong as u8);
                    }

                    // Handle port negotiation and AUTH TLS upgrade.
                    match tx.command {
                        // Active mode: port was parsed from the request line and
                        // stored in tx.dyn_port; only promote on a 200 success
                        // response so a rejected PORT/EPRT doesn't register a
                        // data connection.
                        FtpRequestCommand::FTP_COMMAND_PORT
                        | FtpRequestCommand::FTP_COMMAND_EPRT => {
                            if code == 200 && tx.dyn_port != 0 {
                                new_active_port = tx.dyn_port;
                            }
                        }
                        FtpRequestCommand::FTP_COMMAND_PASV => {
                            if code == 227 {
                                let port = parse_pasv_port(&line);
                                if port != 0 {
                                    tx.dyn_port = port;
                                    tx.active = false;
                                    new_passive_port = port;
                                }
                            }
                        }
                        FtpRequestCommand::FTP_COMMAND_EPSV => {
                            if code == 229 {
                                let port = parse_epsv_port(&line);
                                if port != 0 {
                                    tx.dyn_port = port;
                                    tx.active = false;
                                    new_passive_port = port;
                                }
                            }
                        }
                        _ => {}
                    }

                    if tx.responses.len() < MAX_RESPONSE_LINES
                        && ftp_check_memcap(line.len() as u64)
                    {
                        tx.responses.push(resp);
                    }

                    // Mark complete when we get a final (non-preliminary, non-continuation) reply.
                    if !is_preliminary && !is_continuation {
                        tx.complete = true;
                    }

                    // Promote negotiated port to state level so STOR/RETR can use it.
                    if new_active_port != 0 {
                        self.curr_dyn_port = new_active_port;
                        self.curr_active = true;
                    } else if new_passive_port != 0 {
                        self.curr_dyn_port = new_passive_port;
                        self.curr_active = false;
                    }

                }
            }
        }

        AppLayerResult::ok()
    }

    pub fn on_request_gap(&mut self) {
        self.request_buf.clear();
        self.request_gap = true;
    }

    pub fn on_response_gap(&mut self) {
        self.response_buf.clear();
        self.response_gap = true;
        self.response_multiline_code = None;
    }
}

// ─── C-callable FFI functions ─────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn SCFTPStateNew(
    _orig_state: *mut c_void, _orig_proto: AppProto,
) -> *mut c_void {
    let mut state = FtpState::new();
    state.config = FtpConfig::load();
    Box::into_raw(Box::new(state)) as *mut c_void
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPStateFree(state: *mut c_void) {
    if !state.is_null() {
        drop(Box::from_raw(state as *mut FtpState));
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPStateTransactionFree(state: *mut c_void, tx_id: u64) {
    let state = &mut *(state as *mut FtpState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPParseRequest(
    flow: *mut Flow, state: *mut c_void, pstate: *mut AppLayerParserState,
    stream_slice: suricata_sys::sys::StreamSlice, _data: *mut c_void,
) -> AppLayerResult {
    let eof = SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0;
    if eof {
        return AppLayerResult::ok();
    }
    let state = &mut *(state as *mut FtpState);
    if stream_slice.is_gap() {
        state.on_request_gap();
        return AppLayerResult::ok();
    }
    let buf = stream_slice.as_slice();
    let result = state.parse_request(buf);

    // Drain any FTP-DATA expectations queued during parse_request.
    // We need the Flow pointer here, which parse_request doesn't have.
    for exp in state.pending_expectations.drain(..) {
        SCFTPDataExpectCreate(
            flow,
            exp.file_name.as_ptr(),
            exp.file_name.len() as u32,
            exp.cmd,
            exp.direction,
            exp.dyn_port,
        );
    }

    // Match upstream: trigger raw-stream inspection after processing
    // request-side data.  Without this, detection scheduling for the
    // opposite direction can be off (visible as spurious early alerts on
    // TC-direction engines).
    suricata_sys::sys::SCAppLayerParserTriggerRawStreamInspection(
        flow, STREAM_TOSERVER as c_int,
    );

    result
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPParseResponse(
    flow: *mut Flow, state: *mut c_void, pstate: *mut AppLayerParserState,
    stream_slice: suricata_sys::sys::StreamSlice, _data: *mut c_void,
) -> AppLayerResult {
    let eof = SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0;
    let state = &mut *(state as *mut FtpState);
    if eof {
        // Mark all incomplete transactions complete so rules like
        // ftp.reply_received:no can fire for unanswered commands at flow end.
        for tx in state.transactions.iter_mut() {
            if !tx.complete {
                tx.complete = true;
                tx.tx_data.0.updated_tc = true;
            }
        }
        return AppLayerResult::ok();
    }
    if stream_slice.is_gap() {
        state.on_response_gap();
        return AppLayerResult::ok();
    }
    let buf = stream_slice.as_slice();
    let result = state.parse_response(buf);

    // If the server confirmed AUTH TLS (234), request a TLS upgrade now that
    // we have the Flow pointer.
    if state.auth_tls == AuthTlsState::Confirmed {
        state.auth_tls = AuthTlsState::Idle;
        SCAppLayerRequestProtocolTLSUpgrade(flow);
    }

    // Match upstream: trigger raw-stream inspection after processing
    // response-side data (upstream calls this each time a tx transitions
    // to done).
    suricata_sys::sys::SCAppLayerParserTriggerRawStreamInspection(
        flow, STREAM_TOCLIENT as c_int,
    );

    result
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPGetTx(state: *mut c_void, tx_id: u64) -> *mut c_void {
    let state = &mut *(state as *mut FtpState);
    match state.get_transaction(tx_id) {
        Some(tx) => tx as *const _ as *mut _,
        None => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPGetTxCnt(state: *mut c_void) -> u64 {
    let state = &*(state as *const FtpState);
    state.tx_cnt
}

#[no_mangle]
pub unsafe extern "C" fn SCFTPGetAlstateProgress(tx: *mut c_void, direction: u8) -> c_int {
    let tx = &*(tx as *const FtpTransaction);
    if direction == STREAM_TOSERVER {
        return FtpStateValues::FTP_STATE_FINISHED as c_int;
    }
    if tx.complete {
        FtpStateValues::FTP_STATE_FINISHED as c_int
    } else {
        FtpStateValues::FTP_STATE_IN_PROGRESS as c_int
    }
}

export_tx_data_get!(ftp_get_tx_data, FtpTransaction);
export_state_data_get!(ftp_get_state_data, FtpState);

#[no_mangle]
pub unsafe extern "C" fn SCFTPGetTxIterator(
    _ipproto: u8, _alproto: AppProto, state: *mut c_void, min_tx_id: u64, _max_tx_id: u64,
    istate: *mut AppLayerGetTxIterState,
) -> AppLayerGetTxIterTuple {
    let state = cast_pointer!(state, FtpState);
    state.get_transaction_iterator(min_tx_id, &mut (*istate).un.u64_)
}

// ─── Protocol-detection probing parsers ───────────────────────────────────────

/// Probing parser for `USER ` patterns: disambiguates from POP3, which also
/// begins client sessions with a USER command.
unsafe extern "C" fn ftp_probe_user(
    f: *const Flow, _direction: u8, _input: *const u8, _len: u32, _rdir: *mut u8,
) -> AppProto {
    if !f.is_null() {
        let alproto_pop3 = AppProtoEnum::ALPROTO_POP3 as AppProto;
        if flow_get_alproto_tc(&*f) == alproto_pop3 {
            return ALPROTO_FAILED;
        }
    }
    ALPROTO_FTP
}

/// Probing parser for a QUIT command on port 21 (no embedded keyword match).
unsafe extern "C" fn ftp_probe_quit(
    _f: *const Flow, _direction: u8, input: *const u8, len: u32, _rdir: *mut u8,
) -> AppProto {
    if len < 5 || input.is_null() {
        return ALPROTO_UNKNOWN;
    }
    let slice = std::slice::from_raw_parts(input, len as usize);
    if &slice[..4] != b"QUIT" {
        return ALPROTO_FAILED;
    }
    ALPROTO_FTP
}

/// Server banner probing parser: expects `220 ` or `220-` followed by a line
/// end, but only commits when the client side is FTP or has sent bytes on an
/// otherwise unknown flow (to avoid false positives with SMTP).
unsafe extern "C" fn ftp_probe_server(
    f: *const Flow, _direction: u8, input: *const u8, len: u32, _rdir: *mut u8,
) -> AppProto {
    if len < 5 || input.is_null() {
        return ALPROTO_UNKNOWN;
    }
    let slice = std::slice::from_raw_parts(input, len as usize);
    if slice[0] != b'2' || slice[1] != b'2' || slice[2] != b'0' {
        return ALPROTO_FAILED;
    }
    if slice[3] != b' ' && slice[3] != b'-' {
        return ALPROTO_FAILED;
    }
    if !f.is_null() {
        let alproto_ts = flow_get_alproto_ts(&*f);
        let todst = flow_get_todst_bytecount(&*f);
        if alproto_ts == ALPROTO_FTP || (todst > 4 && alproto_ts == ALPROTO_UNKNOWN) {
            if slice[4..].iter().any(|&b| b == b'\n') {
                return ALPROTO_FTP;
            }
        }
    }
    ALPROTO_UNKNOWN
}

/// Register protocol-detection patterns and probing parsers for FTP on TCP.
/// Mirrors the former C FTPRegisterPatternsForProtocolDetection().
unsafe fn register_patterns_and_probes(ip_proto_str: &CStr) -> i32 {
    let mut r = 0i32;
    r |= SCAppLayerProtoDetectPMRegisterPatternCI(
        IPPROTO_TCP,
        ALPROTO_FTP,
        b"220 (\0".as_ptr() as *const c_char,
        5,
        0,
        STREAM_TOCLIENT,
    );
    r |= SCAppLayerProtoDetectPMRegisterPatternCI(
        IPPROTO_TCP,
        ALPROTO_FTP,
        b"FEAT\0".as_ptr() as *const c_char,
        4,
        0,
        STREAM_TOSERVER,
    );
    r |= SCAppLayerProtoDetectPMRegisterPatternCSwPP(
        IPPROTO_TCP,
        ALPROTO_FTP,
        b"USER \0".as_ptr() as *const c_char,
        5,
        0,
        STREAM_TOSERVER,
        Some(ftp_probe_user),
        5,
        5,
    );
    r |= SCAppLayerProtoDetectPMRegisterPatternCI(
        IPPROTO_TCP,
        ALPROTO_FTP,
        b"PORT \0".as_ptr() as *const c_char,
        5,
        0,
        STREAM_TOSERVER,
    );
    if r < 0 {
        return r;
    }

    // Only check FTP on known ports: the banner has nothing special beyond
    // the response code shared with SMTP.
    let have_cfg = SCAppLayerProtoDetectPPParseConfPorts(
        ip_proto_str.as_ptr(),
        IPPROTO_TCP,
        PARSER_NAME.as_ptr() as *const c_char,
        ALPROTO_FTP,
        0,
        5,
        None,
        Some(ftp_probe_server),
    );
    if have_cfg == 0 {
        // STREAM_TOSERVER uses 21 as flow destination port; ftp_probe_server
        // is the probing parser toward the client side.
        let default_port = CString::new("21").unwrap();
        SCAppLayerProtoDetectPPRegister(
            IPPROTO_TCP,
            default_port.as_ptr(),
            ALPROTO_FTP,
            0,
            5,
            STREAM_TOSERVER,
            Some(ftp_probe_quit),
            Some(ftp_probe_server),
        );
    }
    0
}

// ─── Parser registration ──────────────────────────────────────────────────────

const PARSER_NAME: &[u8] = b"ftp\0";

#[no_mangle]
pub unsafe extern "C" fn SCFTPRegisterParsers() {
    use crate::applayer::{
        applayer_register_protocol_detection, AppLayerRegisterParser, RustParser,
    };

    // Patterns + probing parsers are registered below once ALPROTO_FTP is
    // known; applayer_register_protocol_detection() only calls
    // AppLayerProtoDetectRegisterProtocol() here (default_port is null).
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: std::ptr::null(),
        ipproto: IPPROTO_TCP,
        probe_ts: None,
        probe_tc: None,
        min_depth: 0,
        max_depth: 0,
        state_new: SCFTPStateNew,
        state_free: SCFTPStateFree,
        tx_free: SCFTPStateTransactionFree,
        parse_ts: SCFTPParseRequest,
        parse_tc: SCFTPParseResponse,
        get_tx_count: SCFTPGetTxCnt,
        get_tx: SCFTPGetTx,
        tx_comp_st_ts: FtpStateValues::FTP_STATE_FINISHED as c_int,
        tx_comp_st_tc: FtpStateValues::FTP_STATE_FINISHED as c_int,
        tx_get_progress: SCFTPGetAlstateProgress,
        get_eventinfo: Some(crate::ftp::event::ftp_get_event_info),
        get_eventinfo_byid: Some(crate::ftp::event::ftp_get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(SCFTPGetTxIterator),
        get_tx_data: ftp_get_tx_data,
        get_state_data: ftp_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
        get_state_id_by_name: None,
        get_state_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if SCAppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = applayer_register_protocol_detection(&parser, 1);
        ALPROTO_FTP = alproto;
        if register_patterns_and_probes(ip_proto_str.as_c_str()) < 0 {
            SCLogDebug!("Pattern/probing-parser registration failed for FTP.");
            return;
        }
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
            SCAppLayerParserRegisterLogger(IPPROTO_TCP, alproto);
            SCAppLayerParserRegisterParserAcceptableDataDirection(
                IPPROTO_TCP,
                alproto,
                STREAM_TOSERVER | STREAM_TOCLIENT,
            );
        }
        SCLogDebug!("Rust FTP parser registered.");
    } else {
        SCLogDebug!("Protocol detector and parser disabled for FTP.");
    }
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state() -> FtpState {
        let mut s = FtpState::new();
        // Use small limits for tests.
        s.config.max_tx = 10;
        s.config.max_line_len = 4096;
        s
    }

    #[test]
    fn test_parse_request_user() {
        let mut state = make_state();
        let r = state.parse_request(b"USER anonymous\r\n");
        assert!(r.is_ok());
        assert_eq!(state.tx_cnt, 1);
        let tx = state.get_transaction(0).unwrap();
        assert!(matches!(tx.command, FtpRequestCommand::FTP_COMMAND_USER));
    }

    #[test]
    fn test_parse_response_banner() {
        let mut state = make_state();
        // Server banner before any command.
        let r = state.parse_response(b"220 Welcome\r\n");
        assert!(r.is_ok());
        assert_eq!(state.tx_cnt, 1);
        let tx = state.get_transaction(0).unwrap();
        assert!(tx.complete);
        assert_eq!(tx.responses.len(), 1);
        assert_eq!(tx.responses[0].code, 220);
    }

    #[test]
    fn test_parse_request_port_active() {
        let mut state = make_state();
        let r = state.parse_request(b"PORT 192,168,1,1,0,80\r\n");
        assert!(r.is_ok());
        let tx = state.get_transaction(0).unwrap();
        assert!(matches!(tx.command, FtpRequestCommand::FTP_COMMAND_PORT));
        assert!(tx.active);
        assert_eq!(tx.dyn_port, 80); // 0*256 + 80 = 80
    }

    #[test]
    fn test_parse_response_pasv_port() {
        let mut state = make_state();
        // First create a PASV transaction.
        assert!(state.parse_request(b"PASV\r\n").is_ok());
        assert!(state
            .parse_response(b"227 Entering Passive Mode (192,168,1,1,4,17)\r\n")
            .is_ok());
        let tx = state.get_transaction(0).unwrap();
        assert!(!tx.active);
        assert_eq!(tx.dyn_port, 4 * 256 + 17); // 1041
    }

    #[test]
    fn test_preliminary_response_keeps_tx_open() {
        let mut state = make_state();
        assert!(state.parse_request(b"RETR file.txt\r\n").is_ok());
        // 150 = preliminary, should NOT mark complete.
        assert!(state
            .parse_response(b"150 Opening data connection\r\n")
            .is_ok());
        let tx = state.get_transaction(0).unwrap();
        assert!(!tx.complete);
        // 226 = final.
        assert!(state.parse_response(b"226 Transfer complete\r\n").is_ok());
        let tx = state.get_transaction(0).unwrap();
        assert!(tx.complete);
    }

    #[test]
    fn test_tx_count_limit() {
        let mut state = make_state();
        state.config.max_tx = 2;
        // Slots fill with USER and PASS.  On the third command we hit the
        // limit: the oldest incomplete tx is reaped and tagged with the
        // event, and NO new tx is created (matches upstream tx-cap fix
        // 82c4190558 -- avoids quadratic growth on bursts).
        assert!(state.parse_request(b"USER a\r\n").is_ok());
        assert!(state.parse_request(b"PASS b\r\n").is_ok());
        assert!(state.parse_request(b"NOOP\r\n").is_ok());
        assert_eq!(state.tx_cnt, 2);
        // The first tx (USER) should have been reaped and carry the event.
        let tx = state.get_transaction(0).unwrap();
        assert!(tx.complete);
    }

    #[test]
    fn test_multiple_commands_pipelined() {
        let mut state = make_state();
        let input = b"USER anonymous\r\nPASS secret\r\nPWD\r\n";
        let r = state.parse_request(input);
        assert!(r.is_ok());
        assert_eq!(state.tx_cnt, 3);
    }

    #[test]
    fn test_incomplete_line() {
        let mut state = make_state();
        // Send without \r\n — should buffer and not create transaction.
        assert!(state.parse_request(b"USER anon").is_ok());
        assert_eq!(state.tx_cnt, 0);
        // Complete it.
        assert!(state.parse_request(b"\r\n").is_ok());
        assert_eq!(state.tx_cnt, 1);
    }

    #[test]
    fn test_gap_handling() {
        let mut state = make_state();
        state.on_request_gap();
        assert!(state.request_gap);
        // After next parse, gap is cleared.
        assert!(state.parse_request(b"USER a\r\n").is_ok());
        assert!(!state.request_gap);
    }

    #[test]
    fn test_parse_request_eprt_active() {
        let mut state = make_state();
        assert!(state
            .parse_request(b"EPRT |2|2a01:e34::1|41813|\r\n")
            .is_ok());
        let tx = state.get_transaction(0).unwrap();
        assert!(matches!(tx.command, FtpRequestCommand::FTP_COMMAND_EPRT));
        assert!(tx.active);
        assert_eq!(tx.dyn_port, 41813);
    }

    #[test]
    fn test_parse_response_epsv_port() {
        let mut state = make_state();
        assert!(state.parse_request(b"EPSV\r\n").is_ok());
        assert!(state
            .parse_response(b"229 Entering Extended Passive Mode (|||48758|).\r\n")
            .is_ok());
        let tx = state.get_transaction(0).unwrap();
        assert!(!tx.active);
        assert_eq!(tx.dyn_port, 48758);
    }

    #[test]
    fn test_request_truncation_event() {
        let mut state = make_state();
        state.config.max_line_len = 8;
        assert!(state.parse_request(b"USER anonymous\r\n").is_ok());
        let tx = state.get_transaction(0).unwrap();
        assert!(tx.request_truncated);
    }

    #[test]
    fn test_multiline_response() {
        let mut state = make_state();
        assert!(state.parse_request(b"USER anonymous\r\n").is_ok());
        assert!(state.parse_response(b"331-First line\r\n").is_ok());
        let tx = state.get_transaction(0).unwrap();
        assert!(!tx.complete);
        assert!(state.parse_response(b"331 Second line\r\n").is_ok());
        let tx = state.get_transaction(0).unwrap();
        assert_eq!(tx.responses.len(), 2);
        assert!(tx.complete);
    }

    #[test]
    fn test_case_insensitive_command() {
        let mut state = make_state();
        assert!(state.parse_request(b"user anonymous\r\n").is_ok());
        let tx = state.get_transaction(0).unwrap();
        assert!(matches!(tx.command, FtpRequestCommand::FTP_COMMAND_USER));
    }

    #[test]
    fn test_parse_request_auth_tls() {
        // AUTH TLS does not create a transaction; it sets auth_tls to Requested.
        let mut state = make_state();
        assert!(state.parse_request(b"AUTH TLS\r\n").is_ok());
        assert!(state.transactions.is_empty());
        assert_eq!(state.auth_tls, AuthTlsState::Requested);
    }

    #[test]
    fn test_request_buf_overflow_protection() {
        let mut state = make_state();
        state.config.max_line_len = 16;
        // Feed more than max_line_len bytes without a newline.
        let big = vec![b'A'; 100];
        assert!(state.parse_request(&big).is_ok());
        // Buffer should have been cleared, not grown to 100 bytes.
        assert!(state.request_buf.len() <= 16);
    }

    #[test]
    fn test_response_buf_overflow_protection() {
        let mut state = make_state();
        state.config.max_line_len = 16;
        let big = vec![b'2'; 100];
        assert!(state.parse_response(&big).is_ok());
        assert!(state.response_buf.len() <= 16);
    }

    // Some non-standard FTP servers reply to SYST with a bare line that has no
    // 3-digit response code (e.g. "UNIX Type: L8").  Suricata must advance the
    // oldest incomplete transaction so the next well-formed response (200 for
    // TYPE, then 227 for PASV) lands on the correct transaction.
    #[test]
    fn test_nonstandard_syst_response_does_not_shift_pasv_port() {
        let mut state = make_state();

        // Set up SYST → TYPE → PASV pipeline.
        assert!(state.parse_request(b"SYST\r\n").is_ok());
        assert!(state.parse_request(b"TYPE I\r\n").is_ok());
        assert!(state.parse_request(b"PASV\r\n").is_ok());

        // Non-standard SYST reply (no 3-digit code).
        assert!(state.parse_response(b"UNIX Type: L8\r\n").is_ok());
        // TYPE response.
        assert!(state.parse_response(b"200 Switching to Binary mode\r\n").is_ok());
        // PASV response.
        assert!(state
            .parse_response(b"227 Entering Passive Mode (192,168,1,1,4,17)\r\n")
            .is_ok());

        // The PASV transaction must have the correct port.
        let pasv_tx = state
            .transactions
            .iter()
            .find(|tx| matches!(tx.command, FtpRequestCommand::FTP_COMMAND_PASV))
            .expect("PASV tx not found");
        assert_eq!(pasv_tx.dyn_port, 4 * 256 + 17, "PASV dyn_port should be 1041");
        assert!(!pasv_tx.active);
    }

    // Test that AUTH TLS and AUTH SSL do not create transactions and that
    // USER/PASS responses land on the correct transactions despite the 530
    // rejections that precede them.
    #[test]
    fn test_auth_tls_response_matching() {
        let mut state = make_state();

        // Server banner (comes before any client command).
        assert!(state.parse_response(b"220 vsFTPd 3.0.2\r\n").is_ok());

        // Client sends AUTH TLS — no transaction created.
        assert!(state.parse_request(b"AUTH TLS\r\n").is_ok());

        // Server responds to AUTH TLS with 530.
        assert!(state.parse_response(b"530 Please login with USER and PASS.\r\n").is_ok());

        // Client sends AUTH SSL — no transaction created (UNKNOWN command).
        assert!(state.parse_request(b"AUTH SSL\r\n").is_ok());

        // Server responds to AUTH SSL with 530.
        assert!(state.parse_response(b"530 Please login with USER and PASS.\r\n").is_ok());

        // Client sends USER.
        assert!(state.parse_request(b"USER ftptest\r\n").is_ok());

        // Server responds to USER with 331.
        assert!(state.parse_response(b"331 Please specify the password.\r\n").is_ok());

        // Client sends PASS.
        assert!(state.parse_request(b"PASS 123456\r\n").is_ok());

        // Server responds to PASS with 230.
        assert!(state.parse_response(b"230 Login successful.\r\n").is_ok());

        // AUTH TLS and AUTH SSL must not appear in the transaction list.
        // Both have command_name b"AUTH"; check that no such tx was created.
        assert!(state.transactions.iter()
            .all(|tx| tx.command_name != b"AUTH"),
            "AUTH TLS/SSL should not create transactions");

        let user_tx = state.transactions.iter()
            .find(|tx| matches!(tx.command, FtpRequestCommand::FTP_COMMAND_USER));
        let pass_tx = state.transactions.iter()
            .find(|tx| matches!(tx.command, FtpRequestCommand::FTP_COMMAND_PASS));

        assert!(user_tx.is_some(), "USER transaction not found");
        assert!(pass_tx.is_some(), "PASS transaction not found");

        let user_tx = user_tx.unwrap();
        let pass_tx = pass_tx.unwrap();

        assert_eq!(user_tx.responses.len(), 1, "USER should have 1 response");
        assert_eq!(user_tx.responses[0].code, 331,
            "USER should get 331, not {}", user_tx.responses[0].code);

        assert_eq!(pass_tx.responses.len(), 1, "PASS should have 1 response");
        assert_eq!(pass_tx.responses[0].code, 230,
            "PASS should get 230, not {}", pass_tx.responses[0].code);
    }
}
