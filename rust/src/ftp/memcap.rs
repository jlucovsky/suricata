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

//! FTP memory-cap accounting.
//!
//! Exports the same symbols that the rest of the engine calls by name:
//! `FTPSetMemcap`, `FTPMemuseGlobalCounter`, `FTPMemcapGlobalCounter`,
//! `FTPCalloc`, `FTPRealloc`, `FTPFree`, and `SCFTPInitMemcap`.

use std::os::raw::{c_int, c_void};
use std::sync::atomic::{AtomicU64, Ordering};

use libc::size_t;

static FTP_MEMUSE: AtomicU64 = AtomicU64::new(0);
// FTP_MEMCAP doubles as both the runtime-settable cap and an overflow hit
// counter, matching the pre-existing C semantics.
static FTP_MEMCAP: AtomicU64 = AtomicU64::new(0);
static FTP_CONFIG_MEMCAP: AtomicU64 = AtomicU64::new(0);

pub(super) fn ftp_incr_memuse(size: u64) {
    FTP_MEMUSE.fetch_add(size, Ordering::Relaxed);
}

pub(super) fn ftp_decr_memuse(size: u64) {
    FTP_MEMUSE.fetch_sub(size, Ordering::Relaxed);
}

pub(super) fn ftp_check_memcap(size: u64) -> bool {
    let cap = FTP_CONFIG_MEMCAP.load(Ordering::Relaxed);
    if cap == 0 || size.saturating_add(FTP_MEMUSE.load(Ordering::Relaxed)) <= cap {
        return true;
    }
    FTP_MEMCAP.fetch_add(1, Ordering::Relaxed);
    false
}

#[no_mangle]
pub extern "C" fn FTPMemuseGlobalCounter() -> u64 {
    FTP_MEMUSE.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn FTPMemcapGlobalCounter() -> u64 {
    FTP_MEMCAP.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn FTPSetMemcap(size: u64) -> c_int {
    if size == 0 || FTP_MEMUSE.load(Ordering::Relaxed) < size {
        FTP_CONFIG_MEMCAP.store(size, Ordering::Relaxed);
        return 1;
    }
    0
}

/// Memcap-guarded calloc.  Used for FTP expectation data and as the
/// `Calloc` callback in the streaming buffer config.
///
/// Skips setting `sc_errno`; callers only check the NULL return.
#[no_mangle]
pub unsafe extern "C" fn FTPCalloc(n: size_t, size: size_t) -> *mut c_void {
    let total = n.checked_mul(size).unwrap_or(usize::MAX);
    if !ftp_check_memcap(total as u64) {
        return std::ptr::null_mut();
    }
    let ptr = libc::calloc(n, size);
    if ptr.is_null() {
        return std::ptr::null_mut();
    }
    ftp_incr_memuse(total as u64);
    ptr
}

/// Memcap-guarded realloc.  Used as the `Realloc` callback in the
/// streaming buffer config.
#[no_mangle]
pub unsafe extern "C" fn FTPRealloc(
    ptr: *mut c_void, orig_size: size_t, size: size_t,
) -> *mut c_void {
    if size == 0 {
        libc::free(ptr);
        ftp_decr_memuse(orig_size as u64);
        return std::ptr::null_mut();
    }
    if size > orig_size && !ftp_check_memcap((size - orig_size) as u64) {
        return std::ptr::null_mut();
    }
    let rptr = libc::realloc(ptr, size);
    if rptr.is_null() {
        return std::ptr::null_mut();
    }
    if size > orig_size {
        ftp_incr_memuse((size - orig_size) as u64);
    } else if orig_size > size {
        ftp_decr_memuse((orig_size - size) as u64);
    }
    rptr
}

/// Memcap-tracked free.  Used for FTP expectation data and as the `Free`
/// callback in the streaming buffer config.
#[no_mangle]
pub unsafe extern "C" fn FTPFree(ptr: *mut c_void, size: size_t) {
    libc::free(ptr);
    ftp_decr_memuse(size as u64);
}

/// Called from `SCFTPDataExpectCreate` to track the FtpTransferCmd allocation.
#[no_mangle]
pub extern "C" fn SCFTPIncrMemuse(size: u64) {
    ftp_incr_memuse(size);
}

/// Free callback stored in `FtpTransferCmd.data_free`; called by the
/// expectation engine when the entry is released.
#[no_mangle]
pub unsafe extern "C" fn SCFTPTransferCmdDataFree(data: *mut c_void) {
    use crate::ftp::ftp::{FtpTransferCmd, SCFTPTransferCmdFree};
    let cmd = data as *mut FtpTransferCmd;
    if cmd.is_null() {
        return;
    }
    if !(*cmd).file_name.is_null() {
        FTPFree((*cmd).file_name as *mut c_void, (*cmd).file_len as size_t + 1);
    }
    SCFTPTransferCmdFree(cmd);
    ftp_decr_memuse(std::mem::size_of::<FtpTransferCmd>() as u64);
}

/// Reads the FTP memcap from config and initialises the accounting state.
/// Called once from `RegisterFTPParsers` before any allocations occur.
#[no_mangle]
pub unsafe extern "C" fn SCFTPInitMemcap() {
    let mut memcap: u64 = 0;
    let mut max_tx: u32 = 0;
    let mut max_line_len: u32 = 0;
    crate::ftp::ftp::SCFTPGetConfigValues(&mut memcap, &mut max_tx, &mut max_line_len);
    FTP_CONFIG_MEMCAP.store(memcap, Ordering::Relaxed);
}
