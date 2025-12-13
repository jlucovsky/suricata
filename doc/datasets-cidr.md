# CIDR Dataset Type

## Overview

The CIDR dataset type allows you to define a dataset containing network CIDR blocks (IPv4 and IPv6) and efficiently check if a given IP address falls within any of those CIDR ranges. This is useful for creating allow/deny lists based on network ranges.

## Features

- Supports both IPv4 and IPv6 CIDR notation
- Uses radix tree (trie) data structure for efficient lookups
- O(log n) lookup performance
- Supports both network ranges (e.g., 192.168.0.0/16) and single IPs (e.g., 8.8.8.8)

## Configuration

Add a CIDR dataset in your suricata.yaml:

```yaml
datasets:
  internal-networks:
    type: cidr
    load: internal-networks.txt
```

## Dataset File Format

Each line in the dataset file should contain one CIDR block:

```
# IPv4 CIDR blocks
192.168.0.0/16
10.0.0.0/8
172.16.0.0/12

# Single IPv4 addresses (treated as /32)
8.8.8.8
1.1.1.1

# IPv6 CIDR blocks
2001:db8::/32
fe80::/10

# Single IPv6 addresses (treated as /128)
2001:4860:4860::8888
```

## Usage in Rules

Use the `dataset` keyword in Suricata rules to check if an IP address is within any CIDR in the dataset:

```
# Alert if source IP is in internal networks
alert ip any any -> any any (msg:"Internal IP detected"; dataset:isset,internal-networks,type cidr,ipv4.src; sid:1000001;)

# Alert if destination IP is NOT in allowed networks
alert ip any any -> any any (msg:"External destination"; dataset:isnotset,allowed-networks,type cidr,ipv4.dst; sid:1000002;)
```

## Implementation Details

### Data Structure

The CIDR dataset uses two radix trees internally:
- One for IPv4 addresses (SCRadix4Tree)
- One for IPv6 addresses (SCRadix6Tree)

Both trees are stored in a single CIDRType structure in the dataset hash table.

### Lookup Operation

When checking if an IP address is in the dataset:
1. The appropriate radix tree (IPv4 or IPv6) is selected based on the address type
2. A best-match lookup is performed in the radix tree
3. If a matching CIDR is found, the lookup succeeds

### Performance

- **Add operation**: O(log n) where n is the number of nodes in the radix tree
- **Lookup operation**: O(log n) where n is the number of nodes in the radix tree
- **Memory**: Efficient storage with shared prefixes in the radix tree

## Limitations

- Reputation values are not currently supported for CIDR datasets
- The save functionality (persisting runtime changes) is not yet implemented

## Example Use Cases

1. **Internal Network Detection**: Create a dataset of your internal IP ranges and alert on traffic to/from external IPs
2. **Blocklist**: Maintain a list of malicious IP ranges and block or alert on traffic to/from them
3. **Allowlist**: Define allowed network ranges and alert on traffic outside those ranges
4. **Cloud Provider Networks**: Create datasets of known cloud provider IP ranges for classification

## Files

- `src/datasets-cidr.h` - Header file with CIDRType definition and function declarations
- `src/datasets-cidr.c` - Implementation of CIDR dataset operations
- `src/datasets.c` - Integration with the dataset framework
- `rust/src/detect/datasets.rs` - Rust parser for loading CIDR dataset files
