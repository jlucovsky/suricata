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

//! FTP-DATA EVE JSON logging.  Produces the same `ftp_data` object as the C
//! `EveFTPDataAddMetadata()` in `app-layer-ftp.c`.

use crate::ftp::constant::FtpRequestCommand;
use crate::ftpdata::ftpdata::FtpDataState;
use crate::jsonbuilder::{JsonBuilder, JsonError};

fn log_ftp_data(state: &FtpDataState, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("ftp_data")?;

    if !state.file_name.is_empty() {
        js.set_string_from_bytes("filename", &state.file_name)?;
    }

    match state.command {
        FtpRequestCommand::FTP_COMMAND_STOR => {
            js.set_string("command", "STOR")?;
        }
        FtpRequestCommand::FTP_COMMAND_APPE => {
            js.set_string("command", "APPE")?;
        }
        FtpRequestCommand::FTP_COMMAND_STOU => {
            js.set_string("command", "STOU")?;
        }
        FtpRequestCommand::FTP_COMMAND_RETR => {
            js.set_string("command", "RETR")?;
        }
        FtpRequestCommand::FTP_COMMAND_NLST => {
            js.set_string("command", "NLST")?;
        }
        FtpRequestCommand::FTP_COMMAND_LIST => {
            js.set_string("command", "LIST")?;
        }
        FtpRequestCommand::FTP_COMMAND_MLSD => {
            js.set_string("command", "MLSD")?;
        }
        _ => {}
    }

    js.close()?;
    Ok(())
}

/// Entry point called from C `EveFTPDataAddMetadata`.
#[no_mangle]
pub unsafe extern "C" fn SCFTPDataLogJsonRecord(
    tx: *const std::os::raw::c_void, js: *mut crate::jsonbuilder::JsonBuilder,
) -> bool {
    let state = &*(tx as *const FtpDataState);
    let js = &mut *js;
    log_ftp_data(state, js).is_ok()
}
