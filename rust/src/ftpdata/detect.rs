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

//! FTP-DATA detect support.
//!
//! The `ftpdata_command` keyword match function lives in C (detect-ftpdata.c)
//! and accesses the FTP-DATA state via `SCFTPDataGetCommandValue`, exported
//! here, rather than casting to the Rust struct directly.
//!
//! A full port of the keyword registration is left for a follow-up commit.

// SCFTPDataGetCommandValue is defined in ftpdata.rs and re-exported here
// for documentation purposes.  The symbol is visible to C through the
// normal #[no_mangle] export mechanism.
