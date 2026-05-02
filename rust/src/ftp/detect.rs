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

//! FTP detection keyword support.
//!
//! Each function is callable from C detection code to extract fields from
//! an FtpTransaction for keyword matching.

use crate::detect::uint::{detect_match_uint, DetectUintData};
use crate::ftp::constant::FtpRequestCommand;
use crate::ftp::ftp::{DetectFtpModeData, DetectFtpReplyReceivedData, FtpTransaction};
use std::os::raw::c_void;

// ─── ftp.command sticky buffer ───────────────────────────────────────────────

/// Fill `buf`/`len` with the command name from the transaction.
/// Returns false for UNKNOWN commands or missing request.
#[no_mangle]
pub unsafe extern "C" fn SCFTPGetCommandData(
    tx: *const c_void, _flags: u8, buf: *mut *const u8, len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, FtpTransaction);
    if matches!(tx.command, FtpRequestCommand::FTP_COMMAND_UNKNOWN) {
        return false;
    }
    if tx.command_name.is_empty() {
        return false;
    }
    *buf = tx.command_name.as_ptr();
    *len = tx.command_name.len() as u32;
    true
}

// ─── ftp.command_data sticky buffer ──────────────────────────────────────────

/// Fill `buf`/`len` with the argument portion of the command line.
#[no_mangle]
pub unsafe extern "C" fn SCFTPGetCommandArgData(
    tx: *const c_void, _flags: u8, buf: *mut *const u8, len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, FtpTransaction);
    if matches!(tx.command, FtpRequestCommand::FTP_COMMAND_UNKNOWN) {
        *buf = std::ptr::null();
        *len = 0;
        return false;
    }
    if let Some(ref req) = tx.request {
        if tx.arg_offset < req.len() {
            *buf = req[tx.arg_offset..].as_ptr();
            *len = (req.len() - tx.arg_offset) as u32;
            return true;
        }
    }
    *buf = std::ptr::null();
    *len = 0;
    false
}

// ─── ftp.reply sticky buffer (multi-buffer) ───────────────────────────────────

/// Fill `buf`/`len` with the Nth response message (`local_id`).
/// Sets `*more` to true if there are more response lines after this one.
#[no_mangle]
pub unsafe extern "C" fn SCFTPGetReplyData(
    tx: *const c_void, _flags: u8, local_id: *mut u32, buf: *mut *const u8,
    len: *mut u32, more: *mut bool,
) -> bool {
    let tx = cast_pointer!(tx, FtpTransaction);
    let idx = *local_id as usize;
    if idx >= tx.responses.len() {
        *buf = std::ptr::null();
        *len = 0;
        *more = false;
        return false;
    }
    let resp = &tx.responses[idx];
    *buf = resp.message.as_ptr();
    *len = resp.message.len() as u32;
    *local_id += 1;
    *more = (*local_id as usize) < tx.responses.len();
    true
}

// ─── ftp.completion_code sticky buffer (multi-buffer) ─────────────────────────

/// Fill `buf`/`len` with the Nth 3-char completion code string.
/// Skips continuation lines and code-0 entries, matching the logger.
#[no_mangle]
pub unsafe extern "C" fn SCFTPGetCompletionCodeData(
    tx: *const c_void, _flags: u8, local_id: *mut u32, buf: *mut *const u8,
    len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, FtpTransaction);
    loop {
        let idx = *local_id as usize;
        if idx >= tx.responses.len() {
            *buf = std::ptr::null();
            *len = 0;
            return false;
        }
        *local_id += 1;
        let resp = &tx.responses[idx];
        if resp.is_continuation || resp.code == 0 {
            continue;
        }
        *buf = resp.code_str.as_ptr();
        *len = 3;
        return true;
    }
}

// ─── ftp.mode match ──────────────────────────────────────────────────────────

/// Match active/passive mode.
#[no_mangle]
pub unsafe extern "C" fn SCFTPDetectModeMatch(
    tx: *const c_void, mode_data: *const DetectFtpModeData,
) -> bool {
    let tx = cast_pointer!(tx, FtpTransaction);
    if matches!(tx.command, FtpRequestCommand::FTP_COMMAND_UNKNOWN) {
        return false;
    }
    if tx.dyn_port == 0 {
        return false;
    }
    let md = &*mode_data;
    md.active == tx.active
}

// ─── ftp.reply_received match ─────────────────────────────────────────────────

/// Match whether a reply was received.
#[no_mangle]
pub unsafe extern "C" fn SCFTPDetectReplyReceivedMatch(
    tx: *const c_void, data: *const DetectFtpReplyReceivedData,
) -> bool {
    let tx = cast_pointer!(tx, FtpTransaction);
    if matches!(tx.command, FtpRequestCommand::FTP_COMMAND_UNKNOWN) {
        return false;
    }
    let d = &*data;
    // Match upstream tx->done semantics: a reply is "received" once the
    // final (non-preliminary, non-continuation) response line arrives.
    d.received == tx.complete
}

// ─── ftp.dynamic_port match ───────────────────────────────────────────────────

/// Match the dynamic port number using the full uint match interface
/// (equal, not-equal, range, bitmask, etc.).
///
/// Returns false when no dynamic port is set (dyn_port == 0).
#[no_mangle]
pub unsafe extern "C" fn SCFTPDetectDynPortMatch(
    tx: *const c_void, data: *const DetectUintData<u16>,
) -> bool {
    let tx = cast_pointer!(tx, FtpTransaction);
    if matches!(tx.command, FtpRequestCommand::FTP_COMMAND_UNKNOWN) {
        return false;
    }
    if tx.dyn_port == 0 {
        return false;
    }
    detect_match_uint(&*data, tx.dyn_port)
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ftp::ftp::FtpTransaction;
    use crate::ftp::parser::FtpResponseLine;

    fn make_user_tx() -> FtpTransaction {
        let mut tx = FtpTransaction::new(1);
        tx.command = FtpRequestCommand::FTP_COMMAND_USER;
        tx.command_name = b"USER".to_vec();
        tx.request = Some(b"USER anonymous".to_vec());
        tx.arg_offset = 5; // "USER " = 5
        tx
    }

    fn make_port_tx() -> FtpTransaction {
        let mut tx = FtpTransaction::new(1);
        tx.command = FtpRequestCommand::FTP_COMMAND_PORT;
        tx.command_name = b"PORT".to_vec();
        tx.dyn_port = 1234;
        tx.active = true;
        tx
    }

    #[test]
    fn test_get_command_data() {
        let tx = make_user_tx();
        let mut buf: *const u8 = std::ptr::null();
        let mut len: u32 = 0;
        let result = unsafe { SCFTPGetCommandData(&tx as *const FtpTransaction as *const c_void, 0, &mut buf, &mut len) };
        assert!(result);
        assert_eq!(len, 4);
        let slice = unsafe { std::slice::from_raw_parts(buf, len as usize) };
        assert_eq!(slice, b"USER");
    }

    #[test]
    fn test_get_command_arg_data() {
        let tx = make_user_tx();
        let mut buf: *const u8 = std::ptr::null();
        let mut len: u32 = 0;
        let result = unsafe { SCFTPGetCommandArgData(&tx as *const FtpTransaction as *const c_void, 0, &mut buf, &mut len) };
        assert!(result);
        let slice = unsafe { std::slice::from_raw_parts(buf, len as usize) };
        assert_eq!(slice, b"anonymous");
    }

    #[test]
    fn test_get_command_arg_no_arg() {
        let mut tx = FtpTransaction::new(1);
        tx.command = FtpRequestCommand::FTP_COMMAND_PASV;
        tx.command_name = b"PASV".to_vec();
        tx.request = Some(b"PASV".to_vec());
        tx.arg_offset = 4; // points past end of "PASV"
        let mut buf: *const u8 = std::ptr::null();
        let mut len: u32 = 0;
        let result = unsafe { SCFTPGetCommandArgData(&tx as *const FtpTransaction as *const c_void, 0, &mut buf, &mut len) };
        assert!(!result);
    }

    #[test]
    fn test_get_reply_data() {
        let mut tx = FtpTransaction::new(1);
        tx.command = FtpRequestCommand::FTP_COMMAND_USER;
        tx.command_name = b"USER".to_vec();
        tx.responses.push(FtpResponseLine {
            code: 331,
            is_continuation: false,
            message: b"Password required".to_vec(),
            code_str: [b'3', b'3', b'1'],
        });
        let mut local_id: u32 = 0;
        let mut buf: *const u8 = std::ptr::null();
        let mut len: u32 = 0;
        let mut more: bool = false;
        let result =
            unsafe { SCFTPGetReplyData(&tx as *const FtpTransaction as *const c_void, 0, &mut local_id, &mut buf, &mut len, &mut more) };
        assert!(result);
        assert_eq!(local_id, 1);
        assert!(!more);
        let slice = unsafe { std::slice::from_raw_parts(buf, len as usize) };
        assert_eq!(slice, b"Password required");
    }

    #[test]
    fn test_mode_match_active() {
        let tx = make_port_tx();
        let md = DetectFtpModeData { active: true };
        let result = unsafe { SCFTPDetectModeMatch(&tx as *const FtpTransaction as *const c_void, &md) };
        assert!(result);
    }

    #[test]
    fn test_mode_match_passive_no_match() {
        let tx = make_port_tx();
        let md = DetectFtpModeData { active: false };
        let result = unsafe { SCFTPDetectModeMatch(&tx as *const FtpTransaction as *const c_void, &md) };
        assert!(!result);
    }

    #[test]
    fn test_reply_received_match() {
        let mut tx = make_user_tx();
        tx.complete = true;
        let d = DetectFtpReplyReceivedData { received: true };
        let result = unsafe { SCFTPDetectReplyReceivedMatch(&tx as *const FtpTransaction as *const c_void, &d) };
        assert!(result);

        // received=false, complete=false: rule asks "no reply" and tx has no reply.
        let mut tx2 = make_user_tx();
        tx2.complete = false;
        let d_no = DetectFtpReplyReceivedData { received: false };
        let result2 = unsafe { SCFTPDetectReplyReceivedMatch(&tx2 as *const FtpTransaction as *const c_void, &d_no) };
        assert!(result2);

        // received=true, complete=false: rule asks "reply received" but tx has none — no match.
        let result3 = unsafe { SCFTPDetectReplyReceivedMatch(&tx2 as *const FtpTransaction as *const c_void, &d) };
        assert!(!result3);
    }

    #[test]
    fn test_dyn_port_match() {
        use crate::detect::uint::{DetectUintData, DetectUintMode};
        let tx = make_port_tx();
        let data_match = DetectUintData::<u16> {
            arg1: 1234,
            arg2: 0,
            mode: DetectUintMode::DetectUintModeEqual,
        };
        let result = unsafe { SCFTPDetectDynPortMatch(&tx as *const FtpTransaction as *const c_void, &data_match) };
        assert!(result);
        let data_no_match = DetectUintData::<u16> {
            arg1: 9999,
            arg2: 0,
            mode: DetectUintMode::DetectUintModeEqual,
        };
        let result = unsafe { SCFTPDetectDynPortMatch(&tx as *const FtpTransaction as *const c_void, &data_no_match) };
        assert!(!result);
    }

    #[test]
    fn test_get_completion_code_data() {
        let mut tx = FtpTransaction::new(1);
        tx.command = FtpRequestCommand::FTP_COMMAND_USER;
        tx.command_name = b"USER".to_vec();
        tx.responses.push(FtpResponseLine {
            code: 331,
            is_continuation: false,
            message: b"Password required".to_vec(),
            code_str: [b'3', b'3', b'1'],
        });
        let mut local_id: u32 = 0;
        let mut buf: *const u8 = std::ptr::null();
        let mut len: u32 = 0;
        let result =
            unsafe { SCFTPGetCompletionCodeData(&tx as *const FtpTransaction as *const c_void, 0, &mut local_id, &mut buf, &mut len) };
        assert!(result);
        assert_eq!(len, 3);
        assert_eq!(local_id, 1);
        let slice = unsafe { std::slice::from_raw_parts(buf, len as usize) };
        assert_eq!(slice, b"331");
    }

    #[test]
    fn test_get_reply_data_more() {
        let mut tx = FtpTransaction::new(1);
        tx.command = FtpRequestCommand::FTP_COMMAND_USER;
        tx.command_name = b"USER".to_vec();
        tx.responses.push(FtpResponseLine {
            code: 331,
            is_continuation: true,
            message: b"First".to_vec(),
            code_str: [b'3', b'3', b'1'],
        });
        tx.responses.push(FtpResponseLine {
            code: 331,
            is_continuation: false,
            message: b"Second".to_vec(),
            code_str: [b'3', b'3', b'1'],
        });
        let mut local_id: u32 = 0;
        let mut buf: *const u8 = std::ptr::null();
        let mut len: u32 = 0;
        let mut more: bool = false;

        let result =
            unsafe { SCFTPGetReplyData(&tx as *const FtpTransaction as *const c_void, 0, &mut local_id, &mut buf, &mut len, &mut more) };
        assert!(result);
        assert!(more);
        let slice = unsafe { std::slice::from_raw_parts(buf, len as usize) };
        assert_eq!(slice, b"First");

        let result =
            unsafe { SCFTPGetReplyData(&tx as *const FtpTransaction as *const c_void, 0, &mut local_id, &mut buf, &mut len, &mut more) };
        assert!(result);
        assert!(!more);
        let slice = unsafe { std::slice::from_raw_parts(buf, len as usize) };
        assert_eq!(slice, b"Second");
    }
}
