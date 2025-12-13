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

#include "suricata-common.h"
#include "conf.h"
#include "datasets.h"
#include "datasets-cidr.h"
#include "util-hash-lookup3.h"
#include "util-thash.h"
#include "util-print.h"
#include "util-radix4-tree.h"
#include "util-radix6-tree.h"
#include "util-debug.h"

static SCRadix4Config radix4_cfg = {
    .Free = NULL,
    .PrintData = NULL,
};

static SCRadix6Config radix6_cfg = {
    .Free = NULL,
    .PrintData = NULL,
};

int CIDRSet(void *dst, void *src)
{
    CIDRType *dst_s = dst;

    // Initialize destination trees (empty)
    // For CIDR datasets, we maintain a single entry in the hash table
    // that contains the radix trees for IPv4 and IPv6 CIDRs
    dst_s->ipv4_tree = SCRadix4TreeInitialize();
    dst_s->ipv6_tree = SCRadix6TreeInitialize();

    return 0;
}

bool CIDRCompare(void *a, void *b)
{
    // For hash table purposes, all CIDR dataset entries are considered equal.
    // There is only one entry in the hash table that contains the radix trees.
    return true;
}

uint32_t CIDRHash(uint32_t hash_seed, void *s)
{
    // All CIDR entries hash to the same value so there's only one bucket.
    // This allows us to store a single entry containing the radix trees.
    (void)s;
    return hash_seed;
}

void CIDRFree(void *s)
{
    CIDRType *cidr = s;
    if (cidr) {
        SCRadix4TreeRelease(&cidr->ipv4_tree, &radix4_cfg);
        SCRadix6TreeRelease(&cidr->ipv6_tree, &radix6_cfg);
    }
}

/**
 * \brief Add an IPv4 CIDR string to the dataset
 * \param cidr The CIDR dataset
 * \param ip_str String in format "192.168.1.0/24" or "192.168.1.1"
 * \retval 0 on success
 * \retval -1 on error
 */
int CIDRAddIPv4String(CIDRType *cidr, const char *ip_str)
{
    if (cidr == NULL || ip_str == NULL) {
        return -1;
    }

    // Use the existing radix tree function to add the string
    // This handles both single IPs and CIDR notation
    if (SCRadix4AddKeyIPV4String(&cidr->ipv4_tree, &radix4_cfg, ip_str, NULL)) {
        return 0;
    }

    return -1;
}

/**
 * \brief Add an IPv6 CIDR string to the dataset
 * \param cidr The CIDR dataset
 * \param ip_str String in format "2001:db8::/32" or "2001:db8::1"
 * \retval 0 on success
 * \retval -1 on error
 */
int CIDRAddIPv6String(CIDRType *cidr, const char *ip_str)
{
    if (cidr == NULL || ip_str == NULL) {
        return -1;
    }

    // Use the existing radix tree function to add the string
    // This handles both single IPs and CIDR notation
    if (SCRadix6AddKeyIPV6String(&cidr->ipv6_tree, &radix6_cfg, ip_str, NULL)) {
        return 0;
    }

    return -1;
}

/**
 * \brief Check if an IPv4 address is within any CIDR in the dataset
 * \param cidr The CIDR dataset
 * \param addr IPv4 address (4 bytes)
 * \retval true if address is found
 * \retval false if address is not found
 */
bool CIDRLookupIPv4(const CIDRType *cidr, const uint8_t *addr)
{
    if (cidr == NULL || addr == NULL) {
        return false;
    }

    void *user_data = NULL;
    SCRadix4Node *node = SCRadix4TreeFindBestMatch(&cidr->ipv4_tree, addr, &user_data);

    return (node != NULL);
}

/**
 * \brief Check if an IPv6 address is within any CIDR in the dataset
 * \param cidr The CIDR dataset
 * \param addr IPv6 address (16 bytes)
 * \retval true if address is found
 * \retval false if address is not found
 */
bool CIDRLookupIPv6(const CIDRType *cidr, const uint8_t *addr)
{
    if (cidr == NULL || addr == NULL) {
        return false;
    }

    void *user_data = NULL;
    SCRadix6Node *node = SCRadix6TreeFindBestMatch(&cidr->ipv6_tree, addr, &user_data);

    return (node != NULL);
}

/**
 * \brief Helper function to add a CIDR string to a dataset from Rust
 * \param set The dataset
 * \param cidr_str CIDR string (e.g., "192.168.1.0/24" or "2001:db8::/32")
 * \retval 0 on success
 * \retval -1 on error
 */
int DatasetAddCIDRString(Dataset *set, const char *cidr_str)
{
    if (set == NULL || cidr_str == NULL) {
        return -1;
    }

    if (set->type != DATASET_TYPE_CIDR) {
        SCLogError("DatasetAddCIDRString called on non-CIDR dataset");
        return -1;
    }

    // For CIDR datasets, we use a single hash entry that contains the radix trees
    // We use a dummy lookup to get/create this single entry
    CIDRType lookup;
    memset(&lookup, 0, sizeof(lookup));

    struct THashDataGetResult res = THashGetFromHash(set->hash, &lookup);
    if (!res.data) {
        SCLogError("Failed to get/create CIDR hash entry");
        return -1;
    }

    CIDRType *cidr = res.data->data;

    // Determine if this is IPv4 or IPv6 based on presence of colon
    bool is_ipv6 = (strchr(cidr_str, ':') != NULL);

    int result;
    if (is_ipv6) {
        result = CIDRAddIPv6String(cidr, cidr_str);
    } else {
        result = CIDRAddIPv4String(cidr, cidr_str);
    }

    THashDecrUsecnt(res.data);
    THashDataUnlock(res.data);

    return result;
}
