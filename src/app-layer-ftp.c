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

/**
 * \brief This function is called to retrieve a ftp-data request/response
 * \param ftp_state the ftp data state structure for the parser
 * \param output the resulting output
 *
 * \retval APP_LAYER_OK when input was processed successfully
 * \retval APP_LAYER_ERROR when an unrecoverable error was encountered
 */
static AppLayerResult FTPDataParse(Flow *f, FtpDataState *ftpdata_state,
        AppLayerParserState *pstate, StreamSlice stream_slice, void *local_data, uint8_t direction)
{
    const uint8_t *input = StreamSliceGetData(&stream_slice);
    uint32_t input_len = StreamSliceGetDataLen(&stream_slice);
    const bool eof = (direction & STREAM_TOSERVER)
                             ? SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) != 0
                             : SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) != 0;

    SCTxDataUpdateFileFlags(&ftpdata_state->tx_data, ftpdata_state->state_data.file_flags);
    if (ftpdata_state->tx_data.file_tx == 0)
        ftpdata_state->tx_data.file_tx = direction & (STREAM_TOSERVER | STREAM_TOCLIENT);
    if (direction & STREAM_TOSERVER) {
        ftpdata_state->tx_data.updated_ts = true;
    } else {
        ftpdata_state->tx_data.updated_tc = true;
    }
    /* we depend on detection engine for file pruning */
    const uint16_t flags = SCFileFlowFlagsToFlags(ftpdata_state->tx_data.file_flags, direction);
    int ret = 0;

    SCLogDebug("FTP-DATA input_len %u flags %04x dir %d/%s EOF %s", input_len, flags, direction,
            (direction & STREAM_TOSERVER) ? "toserver" : "toclient", eof ? "true" : "false");

    SCLogDebug("FTP-DATA flags %04x dir %d", flags, direction);
    if (input_len && ftpdata_state->files == NULL) {
        FtpTransferCmd *data =
                (FtpTransferCmd *)SCFlowGetStorageById(f, AppLayerExpectationGetFlowId());
        if (data == NULL) {
            SCReturnStruct(APP_LAYER_ERROR);
        }

        /* we shouldn't get data in the wrong dir. Don't set things up for this dir */
        if ((direction & data->direction) == 0) {
            // TODO set event for data in wrong direction
            SCLogDebug("input %u not for our direction (%s): %s/%s", input_len,
                    (direction & STREAM_TOSERVER) ? "toserver" : "toclient",
                    data->cmd == FTP_COMMAND_STOR ? "STOR" : "RETR",
                    (data->direction & STREAM_TOSERVER) ? "toserver" : "toclient");
            SCReturnStruct(APP_LAYER_OK);
        }

        ftpdata_state->files = FileContainerAlloc();
        if (ftpdata_state->files == NULL) {
            SCFlowFreeStorageById(f, AppLayerExpectationGetFlowId());
            SCReturnStruct(APP_LAYER_ERROR);
        }

        ftpdata_state->file_name = data->file_name;
        ftpdata_state->file_len = data->file_len;
        data->file_name = NULL;
        data->file_len = 0;
        f->parent_id = data->flow_id;
        ftpdata_state->command = data->cmd;
        switch (data->cmd) {
            case FTP_COMMAND_STOR:
                ftpdata_state->direction = data->direction;
                SCLogDebug("STOR data to %s",
                        (ftpdata_state->direction & STREAM_TOSERVER) ? "toserver" : "toclient");
                break;
            case FTP_COMMAND_RETR:
                ftpdata_state->direction = data->direction;
                SCLogDebug("RETR data to %s",
                        (ftpdata_state->direction & STREAM_TOSERVER) ? "toserver" : "toclient");
                break;
            default:
                break;
        }

        /* open with fixed track_id 0 as we can have just one
         * file per ftp-data flow. */
        if (FileOpenFileWithId(ftpdata_state->files, &sbcfg,
                         0ULL, (uint8_t *) ftpdata_state->file_name,
                         ftpdata_state->file_len,
                         input, input_len, flags) != 0) {
            SCLogDebug("Can't open file");
            ret = -1;
        }
        SCFlowFreeStorageById(f, AppLayerExpectationGetFlowId());
        ftpdata_state->tx_data.files_opened = 1;
    } else {
        if ((direction & ftpdata_state->direction) == 0) {
            if (input_len) {
                // TODO set event for data in wrong direction
            }
            SCLogDebug("input %u not for us (%s): %s/%s", input_len,
                    (direction & STREAM_TOSERVER) ? "toserver" : "toclient",
                    ftpdata_state->command == FTP_COMMAND_STOR ? "STOR" : "RETR",
                    (ftpdata_state->direction & STREAM_TOSERVER) ? "toserver" : "toclient");
            SCReturnStruct(APP_LAYER_OK);
        }
        if (ftpdata_state->state == FTPDATA_STATE_FINISHED) {
            SCLogDebug("state is already finished");
            DEBUG_VALIDATE_BUG_ON(input_len); // data after state finished is a bug.
            SCReturnStruct(APP_LAYER_OK);
        }
        if (input_len != 0) {
            ret = FileAppendData(ftpdata_state->files, &sbcfg, input, input_len);
            if (ret == -2) {
                ret = 0;
                SCLogDebug("FileAppendData() - file no longer being extracted");
                goto out;
            } else if (ret < 0) {
                SCLogDebug("FileAppendData() failed: %d", ret);
                ret = -2;
                goto out;
            }
        }
    }

    DEBUG_VALIDATE_BUG_ON((direction & ftpdata_state->direction) == 0); // should be unreachable
    if (eof) {
        ret = FileCloseFile(ftpdata_state->files, &sbcfg, NULL, 0, flags);
        ftpdata_state->state = FTPDATA_STATE_FINISHED;
        SCLogDebug("closed because of eof: state now FTPDATA_STATE_FINISHED");
    }
out:
    if (ret < 0) {
        SCReturnStruct(APP_LAYER_ERROR);
    }
    SCReturnStruct(APP_LAYER_OK);
}

static AppLayerResult FTPDataParseRequest(Flow *f, void *ftp_state, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data)
{
    return FTPDataParse(f, ftp_state, pstate, stream_slice, local_data, STREAM_TOSERVER);
}

static AppLayerResult FTPDataParseResponse(Flow *f, void *ftp_state, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data)
{
    return FTPDataParse(f, ftp_state, pstate, stream_slice, local_data, STREAM_TOCLIENT);
}

#ifdef DEBUG
static SCMutex ftpdata_state_mem_lock = SCMUTEX_INITIALIZER;
static uint64_t ftpdata_state_memuse = 0;
static uint64_t ftpdata_state_memcnt = 0;
#endif

static void *FTPDataStateAlloc(void *orig_state, AppProto proto_orig)
{
    void *s = FTPCalloc(1, sizeof(FtpDataState));
    if (unlikely(s == NULL))
        return NULL;

    FtpDataState *state = (FtpDataState *) s;
    state->state = FTPDATA_STATE_IN_PROGRESS;

#ifdef DEBUG
    SCMutexLock(&ftpdata_state_mem_lock);
    ftpdata_state_memcnt++;
    ftpdata_state_memuse+=sizeof(FtpDataState);
    SCMutexUnlock(&ftpdata_state_mem_lock);
#endif
    return s;
}

static void FTPDataStateFree(void *s)
{
    FtpDataState *fstate = (FtpDataState *) s;

    SCAppLayerTxDataCleanup(&fstate->tx_data);

    if (fstate->file_name != NULL) {
        FTPFree(fstate->file_name, fstate->file_len + 1);
    }

    FileContainerFree(fstate->files, &sbcfg);

    FTPFree(s, sizeof(FtpDataState));
#ifdef DEBUG
    SCMutexLock(&ftpdata_state_mem_lock);
    ftpdata_state_memcnt--;
    ftpdata_state_memuse-=sizeof(FtpDataState);
    SCMutexUnlock(&ftpdata_state_mem_lock);
#endif
}

static AppLayerTxData *FTPDataGetTxData(void *vtx)
{
    FtpDataState *ftp_state = (FtpDataState *)vtx;
    return &ftp_state->tx_data;
}

static AppLayerStateData *FTPDataGetStateData(void *vstate)
{
    FtpDataState *ftp_state = (FtpDataState *)vstate;
    return &ftp_state->state_data;
}

static void FTPDataStateTransactionFree(void *state, uint64_t tx_id)
{
    /* do nothing */
}

static void *FTPDataGetTx(void *state, uint64_t tx_id)
{
    FtpDataState *ftp_state = (FtpDataState *)state;
    return ftp_state;
}

static uint64_t FTPDataGetTxCnt(void *state)
{
    /* ftp-data is single tx */
    return 1;
}

static int FTPDataGetAlstateProgress(void *tx, uint8_t direction)
{
    FtpDataState *ftpdata_state = (FtpDataState *)tx;
    if (direction == ftpdata_state->direction)
        return ftpdata_state->state;
    else
        return FTPDATA_STATE_FINISHED;
}

static AppLayerGetFileState FTPDataStateGetTxFiles(void *tx, uint8_t direction)
{
    FtpDataState *ftpdata_state = (FtpDataState *)tx;
    AppLayerGetFileState files = { .fc = NULL, .cfg = &sbcfg };

    if (direction == ftpdata_state->direction)
        files.fc = ftpdata_state->files;

    return files;
}

bool EveFTPDataAddMetadata(void *vtx, SCJsonBuilder *jb)
{
    const FtpDataState *ftp_state = (FtpDataState *)vtx;
    SCJbOpenObject(jb, "ftp_data");

    if (ftp_state->file_name) {
        SCJbSetStringFromBytes(jb, "filename", ftp_state->file_name, ftp_state->file_len);
    }
    switch (ftp_state->command) {
        case FTP_COMMAND_STOR:
            JB_SET_STRING(jb, "command", "STOR");
            break;
        case FTP_COMMAND_RETR:
            JB_SET_STRING(jb, "command", "RETR");
            break;
        default:
            break;
    }
    SCJbClose(jb);
    return true;
}

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
        AppLayerParserRegisterParser(
                IPPROTO_TCP, ALPROTO_FTPDATA, STREAM_TOSERVER, FTPDataParseRequest);
        AppLayerParserRegisterParser(
                IPPROTO_TCP, ALPROTO_FTPDATA, STREAM_TOCLIENT, FTPDataParseResponse);
        AppLayerParserRegisterStateFuncs(
                IPPROTO_TCP, ALPROTO_FTPDATA, FTPDataStateAlloc, FTPDataStateFree);
        SCAppLayerParserRegisterParserAcceptableDataDirection(
                IPPROTO_TCP, ALPROTO_FTPDATA, STREAM_TOSERVER | STREAM_TOCLIENT);
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_FTPDATA, FTPDataStateTransactionFree);
        AppLayerParserRegisterGetTxFilesFunc(IPPROTO_TCP, ALPROTO_FTPDATA, FTPDataStateGetTxFiles);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_FTPDATA, FTPDataGetTx);
        AppLayerParserRegisterTxDataFunc(IPPROTO_TCP, ALPROTO_FTPDATA, FTPDataGetTxData);
        AppLayerParserRegisterStateDataFunc(IPPROTO_TCP, ALPROTO_FTPDATA, FTPDataGetStateData);
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_FTPDATA, FTPDataGetTxCnt);
        AppLayerParserRegisterGetStateProgressFunc(
                IPPROTO_TCP, ALPROTO_FTPDATA, FTPDataGetAlstateProgress);
        AppLayerParserRegisterStateProgressCompletionStatus(
                ALPROTO_FTPDATA, FTPDATA_STATE_FINISHED, FTPDATA_STATE_FINISHED);
        SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_FTPDATA);

        sbcfg.buf_size = 4096;
        sbcfg.Calloc = FTPCalloc;
        sbcfg.Realloc = FTPRealloc;
        sbcfg.Free = FTPFree;

        FTPParseMemcap();
    } else {
        SCLogInfo("Parser disabled for %s protocol. Protocol detection still on.", proto_name);
    }
}
