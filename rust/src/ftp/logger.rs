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

//! FTP JSON logging.  Produces the same JSON structure as the C
//! `EveFTPLogCommand()` in `output-json-ftp.c`.

use crate::ftp::constant::FtpRequestCommand;
use crate::ftp::ftp::FtpTransaction;
use crate::jsonbuilder::{JsonBuilder, JsonError};

fn log_ftp(tx: &FtpTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("ftp")?;

    // Command name (skip for UNKNOWN).
    let has_command = !matches!(tx.command, FtpRequestCommand::FTP_COMMAND_UNKNOWN)
        && !tx.command_name.is_empty();

    if has_command {
        js.set_string_from_bytes("command", &tx.command_name)?;

        // Command data (argument portion) and truncation flag.
        // command_truncated is only logged when command_data is present,
        // matching the reference C implementation.
        if let Some(ref req) = tx.request {
            let arg = req.get(tx.arg_offset..).unwrap_or(&[]).trim_ascii_end();
            if !arg.is_empty() {
                js.set_string_from_bytes("command_data", arg)?;
                js.set_bool("command_truncated", tx.request_truncated)?;
            }
        }
    }

    // Completion codes array.  Only non-continuation responses carry a completion
    // code; continuation lines (NNN-) and intermediate multi-line lines are skipped.
    let mut reply_truncated = false;
    let mut has_codes = false;
    let mut reply_count = 0usize;

    for resp in &tx.responses {
        if resp.code > 0 && !resp.is_continuation {
            if !has_codes {
                js.open_array("completion_code")?;
                has_codes = true;
            }
            js.append_string_from_bytes(&resp.code_str)?;
        }
        if resp.message.len() > 0 {
            reply_count += 1;
        }
        if !reply_truncated && tx.reply_truncated {
            reply_truncated = true;
        }
    }
    if has_codes {
        js.close()?; // close completion_code array
    }

    // Reply messages array.
    if reply_count > 0 {
        js.open_array("reply")?;
        for resp in &tx.responses {
            if !resp.message.is_empty() {
                js.append_string_from_bytes(&resp.message)?;
            }
        }
        js.close()?; // close reply array
    }

    // Dynamic port.
    if tx.dyn_port != 0 {
        js.set_uint("dynamic_port", tx.dyn_port as u64)?;
    }

    // Mode (only for PORT/EPRT/PASV/EPSV commands).
    match tx.command {
        FtpRequestCommand::FTP_COMMAND_PORT
        | FtpRequestCommand::FTP_COMMAND_EPRT
        | FtpRequestCommand::FTP_COMMAND_PASV
        | FtpRequestCommand::FTP_COMMAND_EPSV => {
            if tx.active {
                js.set_string("mode", "active")?;
            } else {
                js.set_string("mode", "passive")?;
            }
        }
        _ => {}
    }

    // Reply received.
    if tx.reply_received {
        js.set_string("reply_received", "yes")?;
    } else {
        js.set_string("reply_received", "no")?;
    }

    // Reply truncated.
    if reply_truncated {
        js.set_bool("reply_truncated", true)?;
    } else {
        js.set_bool("reply_truncated", false)?;
    }

    js.close()?; // close "ftp" object
    Ok(())
}

/// Entry point called from C `EveFTPLogCommand` replacement.
///
/// # Safety
/// Unsafe due to raw pointer FFI.
#[no_mangle]
pub unsafe extern "C" fn SCFTPLogJsonRecord(
    js: *mut JsonBuilder, tx: *const FtpTransaction,
) -> bool {
    let tx = &*tx;
    let js = &mut *js;
    log_ftp(tx, js).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ftp::ftp::FtpTransaction;
    use crate::ftp::parser::FtpResponseLine;
    use crate::jsonbuilder::JsonBuilder;

    fn get_json(js: &mut JsonBuilder) -> String {
        // Use the C-compatible accessors to get the underlying buffer.
        let len = unsafe { crate::jsonbuilder::SCJbLen(js) };
        let ptr = unsafe { crate::jsonbuilder::SCJbPtr(js) };
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
        String::from_utf8_lossy(bytes).to_string()
    }

    #[test]
    fn test_log_user_command() {
        let mut tx = FtpTransaction::new(1);
        tx.command = FtpRequestCommand::FTP_COMMAND_USER;
        tx.command_name = b"USER".to_vec();
        tx.request = Some(b"USER testuser".to_vec());
        tx.arg_offset = 5;
        tx.complete = true;
        tx.responses.push(FtpResponseLine {
            code: 331,
            is_continuation: false,
            message: b"Password required".to_vec(),
            code_str: [b'3', b'3', b'1'],
        });

        let mut js = JsonBuilder::try_new_object().unwrap();
        log_ftp(&tx, &mut js).unwrap();
        let out = get_json(&mut js);
        assert!(out.contains("\"command\":\"USER\""));
        assert!(out.contains("\"command_data\":\"testuser\""));
        assert!(out.contains("\"reply_received\":\"yes\""));
        assert!(out.contains("\"331\""));
    }

    #[test]
    fn test_log_pasv_command() {
        let mut tx = FtpTransaction::new(1);
        tx.command = FtpRequestCommand::FTP_COMMAND_PASV;
        tx.command_name = b"PASV".to_vec();
        tx.dyn_port = 1234;
        tx.active = false;
        tx.complete = true;

        let mut js = JsonBuilder::try_new_object().unwrap();
        log_ftp(&tx, &mut js).unwrap();
        let out = get_json(&mut js);
        assert!(out.contains("\"mode\":\"passive\""));
        assert!(out.contains("\"dynamic_port\":1234"));
    }

    #[test]
    fn test_log_unknown_command_skips_name() {
        let tx = FtpTransaction::new(1);
        let mut js = JsonBuilder::try_new_object().unwrap();
        log_ftp(&tx, &mut js).unwrap();
        let out = get_json(&mut js);
        // No "command" key for UNKNOWN.
        assert!(!out.contains("\"command\":"));
    }

    #[test]
    fn test_log_port_command() {
        let mut tx = FtpTransaction::new(1);
        tx.command = FtpRequestCommand::FTP_COMMAND_PORT;
        tx.command_name = b"PORT".to_vec();
        tx.dyn_port = 59914;
        tx.active = true;
        tx.complete = true;

        let mut js = JsonBuilder::try_new_object().unwrap();
        log_ftp(&tx, &mut js).unwrap();
        let out = get_json(&mut js);
        assert!(out.contains("\"mode\":\"active\""));
        assert!(out.contains("\"dynamic_port\":59914"));
    }

    #[test]
    fn test_log_multi_reply() {
        // Two separate single-line replies in one transaction (e.g. 150 + 226 for LIST).
        let mut tx = FtpTransaction::new(1);
        tx.command = FtpRequestCommand::FTP_COMMAND_USER;
        tx.command_name = b"USER".to_vec();
        tx.request = Some(b"USER testuser".to_vec());
        tx.arg_offset = 5;
        tx.complete = true;
        tx.reply_received = true;
        tx.responses.push(FtpResponseLine {
            code: 331,
            is_continuation: false,
            message: b"Password".to_vec(),
            code_str: [b'3', b'3', b'1'],
        });
        tx.responses.push(FtpResponseLine {
            code: 230,
            is_continuation: false,
            message: b"Login OK".to_vec(),
            code_str: [b'2', b'3', b'0'],
        });

        let mut js = JsonBuilder::try_new_object().unwrap();
        log_ftp(&tx, &mut js).unwrap();
        let out = get_json(&mut js);
        assert!(out.contains("\"331\""));
        assert!(out.contains("\"230\""));
        assert!(out.contains("\"Password\""));
        assert!(out.contains("\"Login OK\""));
    }

    #[test]
    fn test_log_multiline_response() {
        // RFC 959 multi-line response: "211-text\r\n  line\r\n211 END\r\n".
        // Only the final (non-continuation) code appears in completion_code.
        // The continuation line is stored with its raw "211-..." form.
        let mut tx = FtpTransaction::new(1);
        tx.complete = true;
        tx.reply_received = true;
        tx.responses.push(FtpResponseLine {
            code: 211,
            is_continuation: true,
            message: b"211-Extensions supported:".to_vec(),
            code_str: [b'2', b'1', b'1'],
        });
        tx.responses.push(FtpResponseLine {
            code: 211,
            is_continuation: true,
            message: b"  SIZE".to_vec(),
            code_str: [b'0', b'0', b'0'],
        });
        tx.responses.push(FtpResponseLine {
            code: 211,
            is_continuation: false,
            message: b"END".to_vec(),
            code_str: [b'2', b'1', b'1'],
        });

        let mut js = JsonBuilder::try_new_object().unwrap();
        log_ftp(&tx, &mut js).unwrap();
        let out = get_json(&mut js);
        // Only one "211" in completion_code (the final line).
        let cc_pos = out.find("completion_code").unwrap();
        let cc_section = &out[cc_pos..cc_pos + 30];
        assert!(cc_section.contains("211"), "completion_code should contain 211");
        assert_eq!(out.matches("\"211\"").count(), 1, "211 should appear exactly once");
        assert!(out.contains("211-Extensions supported:"));
        assert!(out.contains("  SIZE"));
        assert!(out.contains("\"END\""));
    }
}
