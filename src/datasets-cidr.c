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

/**
 * \file
 *
 * \author Jeff Lucovsky <jlucovsky@oisf.net>
 */

#include "suricata-common.h"
#include "datasets-cidr.h"
#include "util-ip.h"

static SCRadix4Config radix4_cfg = {
    .Free = NULL,
    .PrintData = NULL,
};

static SCRadix6Config radix6_cfg = {
    .Free = NULL,
    .PrintData = NULL,
};

/**
 * \brief Parse a CIDR notation string into a binary address and prefix length
 * \param cidr_str Input string, e.g. "192.168.1.0/24" or "2001:db8::/32"
 * \param af Address family: AF_INET or AF_INET6
 * \param addr_out Receives the parsed address bytes
 * \param mask_out Receives the prefix length
 * \param max_mask Maximum valid prefix length (32 for IPv4, 128 for IPv6)
 * \retval 0 on success
 * \retval -1 on parse error
 */
static int ParseCIDRString(
        const char *cidr_str, int af, void *addr_out, int *mask_out, int max_mask)
{
    char ip_copy[256];
    strlcpy(ip_copy, cidr_str, sizeof(ip_copy));

    int mask = max_mask;
    char *slash = strchr(ip_copy, '/');
    if (slash != NULL) {
        *slash = '\0';
        const char *prefix_str = slash + 1;
        if (*prefix_str == '\0' || *prefix_str == '-') {
            SCLogError("Invalid CIDR prefix length in '%s'", cidr_str);
            return -1;
        }
        char *endptr = NULL;
        errno = 0;
        long m = strtol(prefix_str, &endptr, 10);
        if (errno != 0 || endptr == prefix_str || *endptr != '\0' || m < 0 || m > max_mask) {
            SCLogError("Invalid CIDR prefix length in '%s'", cidr_str);
            return -1;
        }
        mask = (int)m;
    }

    if (inet_pton(af, ip_copy, addr_out) != 1) {
        SCLogError("Invalid address in '%s'", cidr_str);
        return -1;
    }

    *mask_out = mask;
    return 0;
}

/**
 * \brief Retrieve the CIDRType from a Dataset, validating type and initialization
 * \param set The dataset
 * \retval CIDRType* on success
 * \retval NULL if set is NULL, wrong type, or uninitialized
 */
static inline CIDRType *CIDRFromDataset(const Dataset *set)
{
    if (set == NULL || set->type != DATASET_TYPE_CIDR || set->cidr_data == NULL)
        return NULL;
    return (CIDRType *)set->cidr_data;
}

CIDRType *CIDRNew(uint64_t memcap)
{
    CIDRType *cidr = SCCalloc(1, sizeof(*cidr));
    if (cidr == NULL)
        return NULL;
    cidr->ipv4.tree = SCRadix4TreeInitialize();
    cidr->ipv4.memcap = memcap;
    SCRWLockInit(&cidr->ipv4.lock, NULL);
    cidr->ipv6.tree = SCRadix6TreeInitialize();
    cidr->ipv6.memcap = memcap;
    SCRWLockInit(&cidr->ipv6.lock, NULL);
    return cidr;
}

void CIDRFree(CIDRType *cidr)
{
    if (cidr == NULL)
        return;
    SCRadix4TreeRelease(&cidr->ipv4.tree, &radix4_cfg);
    SCRWLockDestroy(&cidr->ipv4.lock);
    SCRadix6TreeRelease(&cidr->ipv6.tree, &radix6_cfg);
    SCRWLockDestroy(&cidr->ipv6.lock);
    SCFree(cidr);
}

void CIDRClear(CIDRType *cidr)
{
    if (cidr == NULL)
        return;
    SCRWLockWRLock(&cidr->ipv4.lock);
    SCRadix4TreeRelease(&cidr->ipv4.tree, &radix4_cfg);
    cidr->ipv4.tree = SCRadix4TreeInitialize();
    cidr->ipv4.bytes = 0;
    cidr->ipv4.memcap_warned = false;
    SCRWLockUnlock(&cidr->ipv4.lock);

    SCRWLockWRLock(&cidr->ipv6.lock);
    SCRadix6TreeRelease(&cidr->ipv6.tree, &radix6_cfg);
    cidr->ipv6.tree = SCRadix6TreeInitialize();
    cidr->ipv6.bytes = 0;
    cidr->ipv6.memcap_warned = false;
    SCRWLockUnlock(&cidr->ipv6.lock);
}

/**
 * \brief Add a raw-byte IPv4 network entry, enforcing the tree's memcap.
 * \param ipv4 The IPv4 tree wrapper (memcap read from ipv4->memcap)
 * \param set_name Dataset name for the memcap warning log
 * \param addr 4-byte IPv4 address (host bits may be set; will be masked)
 * \param prefix Prefix length (0..32; 32 = host route)
 * \retval 1 if a new entry was inserted
 * \retval 0 if the entry was already present
 * \retval -1 on parameter error
 * \retval -2 on memcap exhaustion
 */
int CIDRAddIPv4Netblock(
        CIDRIPv4Type *ipv4, const char *set_name, const uint8_t *addr, uint8_t prefix)
{
    if (ipv4 == NULL || addr == NULL || prefix > 32)
        return -1;

    uint8_t masked[4];
    memcpy(masked, addr, 4);
    MaskIPNetblock(masked, prefix, 32);

    SCRWLockWRLock(&ipv4->lock);
    void *user_data = NULL;
    SCRadix4Node *existing = SCRadix4TreeFindNetblock(&ipv4->tree, masked, prefix, &user_data);
    int rc;
    if (existing != NULL) {
        rc = 0;
    } else if (ipv4->memcap != 0 && ipv4->bytes + CIDR_IPV4_ENTRY_BYTES > ipv4->memcap) {
        if (!ipv4->memcap_warned) {
            SCLogWarning("CIDR dataset '%s' memcap reached (IPv4), rejecting new entries",
                    set_name ? set_name : "(unknown)");
            ipv4->memcap_warned = true;
        }
        rc = -2;
    } else {
        SCRadix4Node *node = (prefix == 32)
                                     ? SCRadix4AddKeyIPV4(&ipv4->tree, &radix4_cfg, masked, NULL)
                                     : SCRadix4AddKeyIPV4Netblock(
                                               &ipv4->tree, &radix4_cfg, masked, prefix, NULL);
        if (node == NULL) {
            rc = -1;
        } else {
            ipv4->bytes += CIDR_IPV4_ENTRY_BYTES;
            rc = 1;
        }
    }
    SCRWLockUnlock(&ipv4->lock);
    return rc;
}

/**
 * \brief Add a raw-byte IPv6 network entry, enforcing the tree's memcap.
 * \param ipv6 The IPv6 tree wrapper (memcap read from ipv6->memcap)
 * \param set_name Dataset name for the memcap warning log
 * \param addr 16-byte IPv6 address (host bits may be set; will be masked)
 * \param prefix Prefix length (0..128; 128 = host route)
 * \retval 1 if a new entry was inserted
 * \retval 0 if the entry was already present
 * \retval -1 on parameter error
 * \retval -2 on memcap exhaustion
 */
int CIDRAddIPv6Netblock(
        CIDRIPv6Type *ipv6, const char *set_name, const uint8_t *addr, uint8_t prefix)
{
    if (ipv6 == NULL || addr == NULL || prefix > 128)
        return -1;

    uint8_t masked[16];
    memcpy(masked, addr, 16);
    MaskIPNetblock(masked, prefix, 128);

    SCRWLockWRLock(&ipv6->lock);
    void *user_data = NULL;
    SCRadix6Node *existing = SCRadix6TreeFindNetblock(&ipv6->tree, masked, prefix, &user_data);
    int rc;
    if (existing != NULL) {
        rc = 0;
    } else if (ipv6->memcap != 0 && ipv6->bytes + CIDR_IPV6_ENTRY_BYTES > ipv6->memcap) {
        if (!ipv6->memcap_warned) {
            SCLogWarning("CIDR dataset '%s' memcap reached (IPv6), rejecting new entries",
                    set_name ? set_name : "(unknown)");
            ipv6->memcap_warned = true;
        }
        rc = -2;
    } else {
        SCRadix6Node *node = (prefix == 128)
                                     ? SCRadix6AddKeyIPV6(&ipv6->tree, &radix6_cfg, masked, NULL)
                                     : SCRadix6AddKeyIPV6Netblock(
                                               &ipv6->tree, &radix6_cfg, masked, prefix, NULL);
        if (node == NULL) {
            rc = -1;
        } else {
            ipv6->bytes += CIDR_IPV6_ENTRY_BYTES;
            rc = 1;
        }
    }
    SCRWLockUnlock(&ipv6->lock);
    return rc;
}

/**
 * \brief Check if an IPv4 address falls within any CIDR in the tree
 * \param ipv4 The IPv4 tree node
 * \param addr IPv4 address (4 bytes)
 * \retval true if address is covered by a stored prefix
 */
bool CIDRLookupIPv4(CIDRIPv4Type *ipv4, const uint8_t *addr)
{
    if (ipv4 == NULL || addr == NULL)
        return false;

    SCRWLockRDLock(&ipv4->lock);
    void *user_data = NULL; /* required by API, unused */
    SCRadix4Node *node = SCRadix4TreeFindBestMatch(&ipv4->tree, addr, &user_data);
    bool found = (node != NULL);
    SCRWLockUnlock(&ipv4->lock);
    return found;
}

/**
 * \brief Check if an IPv6 address falls within any CIDR in the tree
 * \param ipv6 The IPv6 tree node
 * \param addr IPv6 address (16 bytes)
 * \retval true if address is covered by a stored prefix
 */
bool CIDRLookupIPv6(CIDRIPv6Type *ipv6, const uint8_t *addr)
{
    if (ipv6 == NULL || addr == NULL)
        return false;

    SCRWLockRDLock(&ipv6->lock);
    void *user_data = NULL; /* required by API, unused */
    SCRadix6Node *node = SCRadix6TreeFindBestMatch(&ipv6->tree, addr, &user_data);
    bool found = (node != NULL);
    SCRWLockUnlock(&ipv6->lock);
    return found;
}

/**
 * \brief Remove an exact netblock IPv4 entry if present, under a single write lock
 * \param ipv4 The IPv4 tree node
 * \param addr IPv4 address (4 bytes)
 * \param prefix Prefix length (1-32)
 * \retval true if the entry was found and removed
 * \retval false if the entry was not present
 */
bool CIDRRemoveIPv4Netblock(CIDRIPv4Type *ipv4, const uint8_t *addr, uint8_t prefix)
{
    if (ipv4 == NULL || addr == NULL)
        return false;

    /* The tree stores masked network addresses; mask the query address to match. */
    uint8_t masked[4];
    memcpy(masked, addr, 4);
    MaskIPNetblock(masked, prefix, 32);

    SCRWLockWRLock(&ipv4->lock);
    void *user_data = NULL;
    SCRadix4Node *node = SCRadix4TreeFindNetblock(&ipv4->tree, masked, prefix, &user_data);
    bool found = (node != NULL);
    if (found) {
        SCRadix4RemoveKeyIPV4Netblock(&ipv4->tree, &radix4_cfg, masked, prefix);
        if (ipv4->bytes >= CIDR_IPV4_ENTRY_BYTES)
            ipv4->bytes -= CIDR_IPV4_ENTRY_BYTES;
    }
    SCRWLockUnlock(&ipv4->lock);
    return found;
}

/**
 * \brief Remove an exact netblock IPv6 entry if present, under a single write lock
 * \param ipv6 The IPv6 tree node
 * \param addr IPv6 address (16 bytes)
 * \param prefix Prefix length (1-128)
 * \retval true if the entry was found and removed
 * \retval false if the entry was not present
 */
bool CIDRRemoveIPv6Netblock(CIDRIPv6Type *ipv6, const uint8_t *addr, uint8_t prefix)
{
    if (ipv6 == NULL || addr == NULL)
        return false;

    /* The tree stores masked network addresses; mask the query address to match. */
    uint8_t masked[16];
    memcpy(masked, addr, 16);
    MaskIPNetblock(masked, prefix, 128);

    SCRWLockWRLock(&ipv6->lock);
    void *user_data = NULL;
    SCRadix6Node *node = SCRadix6TreeFindNetblock(&ipv6->tree, masked, prefix, &user_data);
    bool found = (node != NULL);
    if (found) {
        SCRadix6RemoveKeyIPV6Netblock(&ipv6->tree, &radix6_cfg, masked, prefix);
        if (ipv6->bytes >= CIDR_IPV6_ENTRY_BYTES)
            ipv6->bytes -= CIDR_IPV6_ENTRY_BYTES;
    }
    SCRWLockUnlock(&ipv6->lock);
    return found;
}

/**
 * \brief Remove an exact host (/32) IPv4 entry if present, under a single write lock
 * \param ipv4 The IPv4 tree node
 * \param addr IPv4 address (4 bytes)
 * \retval true if the entry was found and removed
 * \retval false if the entry was not present
 */
bool CIDRRemoveIPv4(CIDRIPv4Type *ipv4, const uint8_t *addr)
{
    if (ipv4 == NULL || addr == NULL)
        return false;

    SCRWLockWRLock(&ipv4->lock);
    void *user_data = NULL;
    SCRadix4Node *node = SCRadix4TreeFindExactMatch(&ipv4->tree, addr, &user_data);
    bool found = (node != NULL);
    if (found) {
        SCRadix4RemoveKeyIPV4(&ipv4->tree, &radix4_cfg, addr);
        if (ipv4->bytes >= CIDR_IPV4_ENTRY_BYTES)
            ipv4->bytes -= CIDR_IPV4_ENTRY_BYTES;
    }
    SCRWLockUnlock(&ipv4->lock);
    return found;
}

/**
 * \brief Remove an exact host (/128) IPv6 entry if present, under a single write lock
 * \param ipv6 The IPv6 tree node
 * \param addr IPv6 address (16 bytes)
 * \retval true if the entry was found and removed
 * \retval false if the entry was not present
 */
bool CIDRRemoveIPv6(CIDRIPv6Type *ipv6, const uint8_t *addr)
{
    if (ipv6 == NULL || addr == NULL)
        return false;

    SCRWLockWRLock(&ipv6->lock);
    void *user_data = NULL;
    SCRadix6Node *node = SCRadix6TreeFindExactMatch(&ipv6->tree, addr, &user_data);
    bool found = (node != NULL);
    if (found) {
        SCRadix6RemoveKeyIPV6(&ipv6->tree, &radix6_cfg, addr);
        if (ipv6->bytes >= CIDR_IPV6_ENTRY_BYTES)
            ipv6->bytes -= CIDR_IPV6_ENTRY_BYTES;
    }
    SCRWLockUnlock(&ipv6->lock);
    return found;
}

/**
 * \brief Add a CIDR string to a dataset
 * \param set The dataset
 * \param cidr_str CIDR string (e.g., "192.168.1.0/24" or "2001:db8::/32")
 * \retval 1 on success (added or already present)
 * \retval -1 on error
 */
int DatasetAddCIDRString(Dataset *set, const char *cidr_str)
{
    if (cidr_str == NULL)
        return -1;
    CIDRType *cidr = CIDRFromDataset(set);
    if (cidr == NULL)
        return -1;

    struct in_addr in;
    int mask;
    if (ParseCIDRString(cidr_str, AF_INET, &in, &mask, 32) == 0) {
        int r = CIDRAddIPv4Netblock(
                &cidr->ipv4, set->name, (const uint8_t *)&in.s_addr, (uint8_t)mask);
        return r >= 0 ? r : -1;
    }

    struct in6_addr in6;
    if (ParseCIDRString(cidr_str, AF_INET6, &in6, &mask, 128) == 0) {
        int r = CIDRAddIPv6Netblock(
                &cidr->ipv6, set->name, (const uint8_t *)&in6.s6_addr, (uint8_t)mask);
        return r >= 0 ? r : -1;
    }

    SCLogError("Invalid CIDR address format: %s", cidr_str);
    return -1;
}

/**
 * \brief Remove a CIDR string from a dataset
 * \param set The dataset
 * \param cidr_str CIDR string (e.g., "192.168.1.0/24" or "2001:db8::/32")
 * \retval 1 if removed, 0 if not present
 * \retval -1 on error
 */
int DatasetRemoveCIDRString(Dataset *set, const char *cidr_str)
{
    if (cidr_str == NULL)
        return -1;
    CIDRType *cidr = CIDRFromDataset(set);
    if (cidr == NULL)
        return -1;

    struct in_addr in;
    int mask;
    if (ParseCIDRString(cidr_str, AF_INET, &in, &mask, 32) == 0) {
        return CIDRRemoveIPv4Netblock(&cidr->ipv4, (const uint8_t *)&in.s_addr, (uint8_t)mask) ? 1
                                                                                               : 0;
    }

    struct in6_addr in6;
    if (ParseCIDRString(cidr_str, AF_INET6, &in6, &mask, 128) == 0) {
        return CIDRRemoveIPv6Netblock(&cidr->ipv6, (const uint8_t *)&in6.s6_addr, (uint8_t)mask)
                       ? 1
                       : 0;
    }

    SCLogError("Invalid CIDR address format: %s", cidr_str);
    return -1;
}

/**
 * \brief Look up an IP address in a CIDR dataset
 * \param set The dataset
 * \param ip_str IP string (e.g., "192.168.1.5" or "2001:db8::1")
 * \retval 1 if found
 * \retval 0 if not found
 * \retval -1 on error
 */
int DatasetLookupCIDRString(Dataset *set, const char *ip_str)
{
    if (ip_str == NULL || strlen(ip_str) == 0)
        return -1;
    CIDRType *cidr = CIDRFromDataset(set);
    if (cidr == NULL)
        return -1;

    struct in_addr in;
    if (inet_pton(AF_INET, ip_str, &in) == 1)
        return CIDRLookupIPv4(&cidr->ipv4, (uint8_t *)&in.s_addr) ? 1 : 0;

    struct in6_addr in6;
    if (inet_pton(AF_INET6, ip_str, &in6) == 1)
        return CIDRLookupIPv6(&cidr->ipv6, (uint8_t *)&in6.s6_addr) ? 1 : 0;

    SCLogError("Invalid IP address format: %s", ip_str);
    return -1;
}
