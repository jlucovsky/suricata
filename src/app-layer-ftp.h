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
 * \author Jeff Lucovsky <jeff@lucovsky.org>
 */

#ifndef SURICATA_APP_LAYER_FTP_H
#define SURICATA_APP_LAYER_FTP_H

#include "rust.h"
#include "app-layer-parser.h"

/** FTP Data State for app layer parser */
typedef struct FtpDataState_ {
    uint8_t *input;
    uint8_t *file_name;
    FileContainer *files;
    int32_t input_len;
    int16_t file_len;
    FtpRequestCommand command;
    uint8_t state;
    uint8_t direction;
    AppLayerTxData tx_data;
    AppLayerStateData state_data;
    bool initialized;
} FtpDataState;

void RegisterFTPParsers(void);
int FTPSetMemcap(uint64_t size);
uint64_t FTPMemuseGlobalCounter(void);
uint64_t FTPMemcapGlobalCounter(void);

bool EveFTPDataAddMetadata(void *vtx, SCJsonBuilder *jb);
bool SCFTPDataExpectCreate(Flow *f, const uint8_t *file_name, uint32_t file_name_len, uint8_t cmd,
        uint8_t direction, uint16_t dyn_port);

#endif /* SURICATA_APP_LAYER_FTP_H */
