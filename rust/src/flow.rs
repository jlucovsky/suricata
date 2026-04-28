/* Copyright (C) 2017-2026 Open Information Security Foundation
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

// Flow flags
pub const FLOW_DIR_REVERSED: u64 = BIT_U64!(26);

/// Opaque flow type (defined in C)
pub(crate) use suricata_sys::sys::{
    Flow, SCFlowGetAppProtoTc, SCFlowGetAppProtoTs, SCFlowGetDestinationPort, SCFlowGetFlags,
    SCFlowGetLastTimeAsParts, SCFlowGetSourcePort, SCFlowGetToDstByteCount,
};

/// Return the time of the last flow update as a `Duration`
/// since the epoch.
pub fn flow_get_last_time(flow: &Flow) -> std::time::Duration {
    unsafe {
        let mut secs: u64 = 0;
        let mut usecs: u64 = 0;
        SCFlowGetLastTimeAsParts(flow, &mut secs, &mut usecs);
        std::time::Duration::new(secs, usecs as u32 * 1000)
    }
}

/// Return the flow flags.
pub fn flow_get_flags(flow: &Flow) -> u64 {
    unsafe { SCFlowGetFlags(flow) }
}

/// Return flow ports
pub fn flow_get_ports(flow: &Flow) -> (u16, u16) {
    unsafe { (SCFlowGetSourcePort(flow), SCFlowGetDestinationPort(flow)) }
}

/// Return the app-layer protocol seen so far in the to-server direction.
pub fn flow_get_alproto_ts(flow: &Flow) -> u16 {
    unsafe { SCFlowGetAppProtoTs(flow) }
}

/// Return the app-layer protocol seen so far in the to-client direction.
pub fn flow_get_alproto_tc(flow: &Flow) -> u16 {
    unsafe { SCFlowGetAppProtoTc(flow) }
}

/// Return the byte count sent to the destination (server) on this flow.
pub fn flow_get_todst_bytecount(flow: &Flow) -> u64 {
    unsafe { SCFlowGetToDstByteCount(flow) }
}
