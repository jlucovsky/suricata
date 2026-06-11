/* Copyright (C) 2007-2026 Open Information Security Foundation
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

/**
 * \file
 *
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 * \author Eric Leblond <eric@regit.org>
 * \author Jeff Lucovsky <jlucovsky@oisf.net>
 *
 * App Layer Parser for FTP (FTP-DATA only; FTP command parser is in Rust)
 */

#include "suricata-common.h"

#include "app-layer-ftp.h"
#include "app-layer-expectation.h"

#include "rust.h"

#include "util-misc.h"
#include "util-validate.h"


/**
 * \brief Bridge called from Rust SCFTPParseRequest when a STOR/RETR expectation
 *        is needed.  Allocates FtpTransferCmd, fills it from the Rust-side
 *        PendingExpectation fields, and registers it with AppLayerExpectationCreate.
 */
bool SCFTPDataExpectCreate(Flow *f, const uint8_t *file_name, uint32_t file_name_len, uint8_t cmd,
        uint8_t direction, uint16_t dyn_port)
{
    FtpTransferCmd *data = SCFTPTransferCmdNew();
    if (data == NULL)
        return false;
    SCFTPIncrMemuse((uint64_t)sizeof(*data));
    data->data_free = SCFTPTransferCmdDataFree;

    uint32_t fname_len = MIN(SC_FILENAME_MAX - 1, file_name_len);
    data->file_name = FTPCalloc(fname_len + 1, sizeof(char));
    if (data->file_name == NULL) {
        SCFTPTransferCmdDataFree(data);
        return false;
    }
    data->file_name[fname_len] = 0;
    data->file_len = (uint16_t)fname_len;
    memcpy(data->file_name, file_name, fname_len);
    data->cmd = cmd;
    data->flow_id = FlowGetId(f);
    data->direction = direction;

    int ret = AppLayerExpectationCreate(f, direction, 0, dyn_port, ALPROTO_FTPDATA, data);
    if (ret == -1) {
        SCFTPTransferCmdDataFree(data);
        SCLogDebug("No expectation created.");
        return false;
    }
    SCLogDebug("Expectation created [direction: %s, dynamic port %" PRIu16 "].",
            (direction & STREAM_TOCLIENT) ? "to client" : "to server", dyn_port);
    return true;
}

const FtpTransferCmd *SCFTPDataFlowGetTransferCmd(const Flow *f)
{
    return (const FtpTransferCmd *)SCFlowGetStorageById(f, AppLayerExpectationGetFlowId());
}

void SCFTPDataFlowFreeTransferCmd(Flow *f)
{
    SCFlowFreeStorageById(f, AppLayerExpectationGetFlowId());
}

void SCFTPDataFlowSetParentId(Flow *f, uint64_t parent_id)
{
    f->parent_id = parent_id;
}
