/* Copyright (C) 2021-2022 Open Information Security Foundation
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
 *
 * Implements the quic.cyu.string sticky buffer
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-quic-cyu-string.h"
#include "detect-engine-build.h"
#include "rust.h"
#include "util-profiling.h"

#ifdef UNITTESTS
static void DetectQuicCyuStringRegisterTests(void);
#endif

#define KEYWORD_NAME "quic.cyu.string"
#define KEYWORD_DOC  "quic-cyu.html#quic-cyu-string"
#define BUFFER_NAME  "quic.cyu.string"
#define BUFFER_DESC  "QUIC CYU String"
static int g_buffer_id = 0;

struct QuicStringGetDataArgs {
    uint32_t local_id; /**< used as index into thread inspect array */
    void *txv;
};

static int DetectQuicCyuStringSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(s, g_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_QUIC) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *QuicStringGetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, struct QuicStringGetDataArgs *cbdata,
        int list_id, bool first)
{
    SCEnter();

    InspectionBuffer *buffer =
            InspectionBufferMultipleForListGet(det_ctx, list_id, cbdata->local_id);
    if (buffer == NULL)
        return NULL;
    if (!first && buffer->inspect != NULL)
        return buffer;

    const uint8_t *data;
    uint32_t data_len;
    if (rs_quic_tx_get_cyu_string(cbdata->txv, cbdata->local_id, &data, &data_len) == 0) {
        return NULL;
    }

    InspectionBufferSetupMulti(buffer, transforms, data, data_len);

    SCReturnPtr(buffer, "InspectionBuffer");
}

static uint8_t DetectEngineInspectQuicString(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const DetectEngineAppInspectionEngine *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    uint32_t local_id = 0;

    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v2.transforms;
    }

    while (1) {
        struct QuicStringGetDataArgs cbdata = {
            local_id,
            txv,
        };
        InspectionBuffer *buffer =
                QuicStringGetData(det_ctx, transforms, f, &cbdata, engine->sm_list, false);
        if (buffer == NULL || buffer->inspect == NULL)
            break;

        det_ctx->buffer_offset = 0;
        det_ctx->discontinue_matching = 0;
        det_ctx->inspection_recursion_counter = 0;

        const int match = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd, NULL, f,
                (uint8_t *)buffer->inspect, buffer->inspect_len, buffer->inspect_offset,
                DETECT_CI_FLAGS_SINGLE, DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
        if (match == 1) {
            return DETECT_ENGINE_INSPECT_SIG_MATCH;
        }
        local_id++;
    }
    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

/** \brief QuicString Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxQuicString(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p,
        Flow *f, void *txv, const uint64_t idx, const AppLayerTxData *_txd, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmListId *ctx = (const PrefilterMpmListId *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;

    uint32_t local_id = 0;
    while (1) {
        // loop until we get a NULL

        struct QuicStringGetDataArgs cbdata = { local_id, txv };
        InspectionBuffer *buffer =
                QuicStringGetData(det_ctx, ctx->transforms, f, &cbdata, list_id, true);
        if (buffer == NULL)
            break;

        if (buffer->inspect_len >= mpm_ctx->minlen) {
            (void)mpm_table[mpm_ctx->mpm_type].Search(
                    mpm_ctx, &det_ctx->mtcu, &det_ctx->pmq, buffer->inspect, buffer->inspect_len);
            PREFILTER_PROFILING_ADD_BYTES(det_ctx, buffer->inspect_len);
        }

        local_id++;
    }
}

static void PrefilterMpmListIdFree(void *ptr)
{
    SCFree(ptr);
}

static int PrefilterMpmListIdRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistery *mpm_reg, int list_id)
{
    PrefilterMpmListId *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    return PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTxQuicString, mpm_reg->app_v2.alproto,
            mpm_reg->app_v2.tx_min_progress, pectx, PrefilterMpmListIdFree, mpm_reg->pname);
}

void DetectQuicCyuStringRegister(void)
{
    /* quic.cyu.string sticky buffer */
    sigmatch_table[DETECT_AL_QUIC_CYU_STRING].name = KEYWORD_NAME;
    sigmatch_table[DETECT_AL_QUIC_CYU_STRING].desc =
            "sticky buffer to match on the QUIC CYU string";
    sigmatch_table[DETECT_AL_QUIC_CYU_STRING].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_AL_QUIC_CYU_STRING].Setup = DetectQuicCyuStringSetup;
    sigmatch_table[DETECT_AL_QUIC_CYU_STRING].flags |= SIGMATCH_NOOPT;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_QUIC_CYU_STRING].RegisterTests = DetectQuicCyuStringRegisterTests;
#endif

    DetectAppLayerMpmRegister2(
            BUFFER_NAME, SIG_FLAG_TOSERVER, 2, PrefilterMpmListIdRegister, NULL, ALPROTO_QUIC, 1);

    DetectAppLayerInspectEngineRegister2(
            BUFFER_NAME, ALPROTO_QUIC, SIG_FLAG_TOSERVER, 0, DetectEngineInspectQuicString, NULL);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME, BUFFER_DESC);

    g_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);

    SCLogDebug("registering " BUFFER_NAME " rule option");
}

#ifdef UNITTESTS
#include "app-layer-parser.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "flow-util.h"
#include "detect-engine-alert.h"

/**
 * \test DetectQuicCyuStringTest01 is a test for a valid quic packet, matching
 *   on the cyu string
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int DetectQuicCyuStringTest01(void)
{
    /* quic packet */
    uint8_t buf[] = { 0xc3, 0x51, 0x30, 0x34, 0x36, 0x50, 0x76, 0xd8, 0x63, 0xb7, 0x54, 0xf7, 0xab,
        0x32, 0x00, 0x00, 0x00, 0x01, 0x54, 0xfd, 0xf4, 0x79, 0x48, 0x76, 0xd0, 0x87, 0x58, 0x8d,
        0x26, 0x8f, 0xa0, 0x01, 0x04, 0x00, 0x43, 0x48, 0x4c, 0x4f, 0x11, 0x00, 0x00, 0x00, 0x50,
        0x41, 0x44, 0x00, 0xe4, 0x02, 0x00, 0x00, 0x53, 0x4e, 0x49, 0x00, 0xf7, 0x02, 0x00, 0x00,
        0x56, 0x45, 0x52, 0x00, 0xfb, 0x02, 0x00, 0x00, 0x43, 0x43, 0x53, 0x00, 0x0b, 0x03, 0x00,
        0x00, 0x55, 0x41, 0x49, 0x44, 0x2c, 0x03, 0x00, 0x00, 0x54, 0x43, 0x49, 0x44, 0x30, 0x03,
        0x00, 0x00, 0x50, 0x44, 0x4d, 0x44, 0x34, 0x03, 0x00, 0x00, 0x53, 0x4d, 0x48, 0x4c, 0x38,
        0x03, 0x00, 0x00, 0x49, 0x43, 0x53, 0x4c, 0x3c, 0x03, 0x00, 0x00, 0x4e, 0x4f, 0x4e, 0x50,
        0x5c, 0x03, 0x00, 0x00, 0x4d, 0x49, 0x44, 0x53, 0x60, 0x03, 0x00, 0x00, 0x53, 0x43, 0x4c,
        0x53, 0x64, 0x03, 0x00, 0x00, 0x43, 0x53, 0x43, 0x54, 0x64, 0x03, 0x00, 0x00, 0x43, 0x4f,
        0x50, 0x54, 0x64, 0x03, 0x00, 0x00, 0x49, 0x52, 0x54, 0x54, 0x68, 0x03, 0x00, 0x00, 0x43,
        0x46, 0x43, 0x57, 0x6c, 0x03, 0x00, 0x00, 0x53, 0x46, 0x43, 0x57, 0x70, 0x03, 0x00, 0x00,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x73, 0x31, 0x2e, 0x67,
        0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x51, 0x30, 0x34, 0x36, 0x01, 0xe8,
        0x81, 0x60, 0x92, 0x92, 0x1a, 0xe8, 0x7e, 0xed, 0x80, 0x86, 0xa2, 0x15, 0x82, 0x91, 0x43,
        0x68, 0x72, 0x6f, 0x6d, 0x65, 0x2f, 0x37, 0x39, 0x2e, 0x30, 0x2e, 0x33, 0x39, 0x34, 0x35,
        0x2e, 0x31, 0x31, 0x37, 0x20, 0x4c, 0x69, 0x6e, 0x75, 0x78, 0x20, 0x78, 0x38, 0x36, 0x5f,
        0x36, 0x34, 0x00, 0x00, 0x00, 0x00, 0x58, 0x35, 0x30, 0x39, 0x01, 0x00, 0x00, 0x00, 0x1e,
        0x00, 0x00, 0x00, 0x82, 0x88, 0x09, 0x00, 0xfa, 0x0f, 0xde, 0xb7, 0x2e, 0x7e, 0x6c, 0x78,
        0xcc, 0x09, 0x65, 0xab, 0x06, 0x0c, 0x31, 0x05, 0xfa, 0xd9, 0xa2, 0x0b, 0xdd, 0x74, 0x5c,
        0x28, 0xdf, 0x7b, 0x74, 0x23, 0x64, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1d, 0x43,
        0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00 };

    Flow f;
    void *quic_state = NULL;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_UDP, "192.168.1.5", "192.168.1.1", 41424, 443);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOSERVER;
    f.alproto = ALPROTO_QUIC;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert quic any any -> any any "
                                      "(msg:\"Test QUIC CYU string\"; "
                                      "quic.cyu.string; "
                                      "content:\"46,PAD-SNI-VER-CCS-UAID-TCID-PDMD-SMHL-ICSL-NONP-"
                                      "MIDS-SCLS-CSCT-COPT-IRTT-CFCW-SFCW\"; "
                                      "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_QUIC, STREAM_TOSERVER, buf, sizeof(buf));
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    quic_state = f.alstate;
    FAIL_IF_NULL(quic_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert, but it should have: ");
        FAIL;
    }

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;
}

/**
 * \brief this function registers unit tests for Quic Cyu String
 */
static void DetectQuicCyuStringRegisterTests(void)
{
    UtRegisterTest("DetectQuicCyuStringTest01", DetectQuicCyuStringTest01);
}

#endif /* UNITTESTS */