/* Copyright (C) 2025 Open Information Security Foundation
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
 * \author Jason Lucovsky <jlucovsky@oisf.net>
 */

#ifndef SURICATA_DATASETS_CIDR_H
#define SURICATA_DATASETS_CIDR_H

#include "util-radix4-tree.h"
#include "util-radix6-tree.h"

typedef struct Dataset Dataset;

typedef struct CIDRType {
    SCRadix4Tree ipv4_tree;
    SCRadix6Tree ipv6_tree;
} CIDRType;

int CIDRSet(void *dst, void *src);
bool CIDRCompare(void *a, void *b);
uint32_t CIDRHash(uint32_t hash_seed, void *s);
void CIDRFree(void *s);

int CIDRAddIPv4String(CIDRType *cidr, const char *ip_str);
int CIDRAddIPv6String(CIDRType *cidr, const char *ip_str);

bool CIDRLookupIPv4(const CIDRType *cidr, const uint8_t *addr);
bool CIDRLookupIPv6(const CIDRType *cidr, const uint8_t *addr);

int DatasetAddCIDRString(Dataset *set, const char *cidr_str);

#endif /* SURICATA_DATASETS_CIDR_H */
