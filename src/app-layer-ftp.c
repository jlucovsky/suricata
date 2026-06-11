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
#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-expectation.h"
#include "app-layer-detect-proto.h"

#include "rust.h"

#include "util-misc.h"
#include "util-validate.h"

uint64_t ftp_config_memcap = 0;
uint32_t ftp_config_maxtx = 1024;
uint32_t ftp_max_line_len = 4096;

SC_ATOMIC_DECLARE(uint64_t, ftp_memuse);
SC_ATOMIC_DECLARE(uint64_t, ftp_memcap);

static void FTPParseMemcap(void)
{
    SCFTPGetConfigValues(&ftp_config_memcap, &ftp_config_maxtx, &ftp_max_line_len);

    SC_ATOMIC_INIT(ftp_memuse);
    SC_ATOMIC_INIT(ftp_memcap);
}

static void FTPIncrMemuse(uint64_t size)
{
    (void)SC_ATOMIC_ADD(ftp_memuse, size);
}

static void FTPDecrMemuse(uint64_t size)
{
    (void)SC_ATOMIC_SUB(ftp_memuse, size);
}

uint64_t FTPMemuseGlobalCounter(void)
{
    uint64_t tmpval = SC_ATOMIC_GET(ftp_memuse);
    return tmpval;
}

uint64_t FTPMemcapGlobalCounter(void)
{
    uint64_t tmpval = SC_ATOMIC_GET(ftp_memcap);
    return tmpval;
}

int FTPSetMemcap(uint64_t size)
{
    if ((uint64_t)SC_ATOMIC_GET(ftp_memcap) < size) {
        SC_ATOMIC_SET(ftp_memcap, size);
        return 1;
    }

    return 0;
}

/**
 *  \brief Check if alloc'ing "size" would mean we're over memcap
 *
 *  \retval 1 if in bounds
 *  \retval 0 if not in bounds
 */
static int FTPCheckMemcap(uint64_t size)
{
    if (ftp_config_memcap == 0 || size + SC_ATOMIC_GET(ftp_memuse) <= ftp_config_memcap)
        return 1;
    (void) SC_ATOMIC_ADD(ftp_memcap, 1);
    return 0;
}

static void *FTPCalloc(size_t n, size_t size)
{
    if (FTPCheckMemcap((uint32_t)(n * size)) == 0) {
        sc_errno = SC_ELIMIT;
        return NULL;
    }

    void *ptr = SCCalloc(n, size);

    if (unlikely(ptr == NULL)) {
        sc_errno = SC_ENOMEM;
        return NULL;
    }

    FTPIncrMemuse((uint64_t)(n * size));
    return ptr;
}

static void *FTPRealloc(void *ptr, size_t orig_size, size_t size)
{
    if (FTPCheckMemcap((uint32_t)(size - orig_size)) == 0) {
        sc_errno = SC_ELIMIT;
        return NULL;
    }

    void *rptr = SCRealloc(ptr, size);
    if (rptr == NULL) {
        sc_errno = SC_ENOMEM;
        return NULL;
    }

    if (size > orig_size) {
        FTPIncrMemuse(size - orig_size);
    } else {
        FTPDecrMemuse(orig_size - size);
    }

    return rptr;
}

static void FTPFree(void *ptr, size_t size)
{
    SCFree(ptr);

    FTPDecrMemuse((uint64_t)size);
}

static void FtpTransferCmdFree(void *data)
{
    FtpTransferCmd *cmd = (FtpTransferCmd *)data;
    if (cmd == NULL)
        return;
    if (cmd->file_name) {
        FTPFree((void *)cmd->file_name, cmd->file_len + 1);
    }
    SCFTPTransferCmdFree(cmd);
    FTPDecrMemuse((uint64_t)sizeof(FtpTransferCmd));
}

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
    FTPIncrMemuse((uint64_t)sizeof(*data));
    data->data_free = FtpTransferCmdFree;

    uint32_t fname_len = MIN(SC_FILENAME_MAX - 1, file_name_len);
    data->file_name = FTPCalloc(fname_len + 1, sizeof(char));
    if (data->file_name == NULL) {
        FtpTransferCmdFree(data);
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
        FtpTransferCmdFree(data);
        SCLogDebug("No expectation created.");
        return false;
    }
    SCLogDebug("Expectation created [direction: %s, dynamic port %" PRIu16 "].",
            (direction & STREAM_TOCLIENT) ? "to client" : "to server", dyn_port);
    return true;
}

static StreamingBufferConfig sbcfg = STREAMING_BUFFER_CONFIG_INITIALIZER;

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

const StreamingBufferConfig *SCFTPDataGetSbcfg(void)
{
    return &sbcfg;
}

/* FTPData parser functions moved to Rust (rust/src/ftpdata/ftpdata.rs).
 * Bridge entry points (SCFTPDataFlowGetTransferCmd etc.) remain above.
 */

void RegisterFTPParsers(void)
{
    const char *proto_name = "ftp";
    const char *proto_data_name = "ftp-data";

    if (SCAppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_FTPDATA, proto_data_name);
    }

    /* Register the Rust FTP command parser (handles FTP protocol detection,
     * state machine, transactions, and probing parsers). */
    SCFTPRegisterParsers();

    if (SCAppLayerParserConfParserEnabled("tcp", proto_name)) {
        AppLayerRegisterExpectationProto(IPPROTO_TCP, ALPROTO_FTPDATA);

        sbcfg.buf_size = 4096;
        sbcfg.Calloc = FTPCalloc;
        sbcfg.Realloc = FTPRealloc;
        sbcfg.Free = FTPFree;

        SCFTPDataRegisterParsers(ALPROTO_FTPDATA);

        FTPParseMemcap();
    } else {
        SCLogInfo("Parser disabled for %s protocol. Protocol detection still on.", proto_name);
    }
}
