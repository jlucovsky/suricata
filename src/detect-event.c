/* Copyright (C) 2022 Open Information Security Foundation
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
 * \author Jeff Lucovsky <jlucovsky@oisf.net>
 *
 * Implements event keyword support
 *
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-event.h"
#include "detect-engine.h"
#include "util-unittest.h"
#include "util-validate.h"

static int DetectEventSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectEventRegisterTests(void);
#endif

void DetectEventRegister(void)
{
    sigmatch_table[DETECT_EVENT].name = "event";
    sigmatch_table[DETECT_EVENT].desc = "used for signaling to alert consumers";
    sigmatch_table[DETECT_EVENT].url = "/rules/meta.html#event";
    sigmatch_table[DETECT_EVENT].Match = NULL;
    sigmatch_table[DETECT_EVENT].Setup = DetectEventSetup;
    sigmatch_table[DETECT_EVENT].Free = NULL;
#ifdef UNITTESTS
    sigmatch_table[DETECT_EVENT].RegisterTests = DetectEventRegisterTests;
#endif
}

static int DetectEventParse(DetectEngineCtx *de_ctx, Signature *s, const char *eventstr)
{

    if (!eventstr || strlen(eventstr) == 0) {
        return -1;
    }

    s->eventstr = SCStrdup(eventstr);
    return 0;
}

static int DetectEventSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectEventParse(de_ctx, s, rawstr);

    return 0;
}

#ifdef UNITTESTS

static int DetectEventParseTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                   "(event: annabelle; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);
    FAIL_IF_NULL(sig->eventstr);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectEventParseTest02(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    Signature *sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                   "(event: nash; "
                                                   "sid:1; rev:1;)");
    FAIL_IF_NULL(sig);
    FAIL_IF_NULL(sig->eventstr);
    FAIL_IF(strcmp("nash", sig->eventstr));
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \brief this function registers unit tests for DetectEventService
 */
static void DetectEventRegisterTests(void)
{
    UtRegisterTest("DetectEventParseTest01", DetectEventParseTest01);
    UtRegisterTest("DetectEventParseTest02", DetectEventParseTest02);
}
#endif /* UNITTESTS */
