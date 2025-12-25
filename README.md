# BTCap — Bluetooth Low Energy Capture & Correlation Tool

BTCap is a Bluetooth Low Energy (BLE) PCAP analysis tool focused on session reconstruction, ATT event correlation, and structured visualization.
It is designed for security analysis, protocol inspection, and educational use, providing a workflow similar to tools like Wireshark, gatttool, or bettercap BLE — but optimized for command-line, correlation-first analysis.

## Features
- Load and dissect BLE PCAP / PCAPNG files
- Automatically detect BLE connections (sessions)
- Group packets by Access Address
- Track connection lifecycle:
  - CONNECT_IND
  - ATT traffic
  - TERMINATE_IND
- Parse and classify ATT operations:
  - Read Request / Response
  - Write Request / Response
  - Write Command
  - Notifications
- Correlate request → response events
- Multiple visualization formats:
  - Packet summary
  - Tree view (correlated events)
  - Detailed packet view
  - Hexdump view
- Interactive CLI with context-aware commands

## Commands
### session
List or select BLE sessions.
```bash
session
session <id>
```

Examples:
```bash
session
session 0
```
### show

Display session data in different formats.
```bash
show pcap
show tree
show packet <id>
```

- `pcap`: raw packet summaries
- `tree`: correlated ATT request/response tree
- `packet`: show a specific packet using the current view mode

### set

Change visualization settings.
```bash
set view <brief | details | hexdump>
```

- `brief`: one-line summary
- `details`: full Scapy .show()
- `hexdump`: raw bytes + decoded value (if present)


## Usage Example
```bash
python3 btcap/main.py capture.pcapng

btcap > session
btcap > session 0
btcap(session:0) > show tree
btcap(session:0) > set view hexdump
btcap(session:0) > show packet 42
```

> ⚠️ Important:
This tool currently assumes a well-formed BLE capture.

### Known limitations:
- No handling of:
  - Reordered packets
  - Packet loss
  - Concurrent outstanding ATT requests
- Correlation assumes:
  - One request → one response
  - FIFO ordering
- Encryption handling is limited:
  - Encrypted ATT traffic is parsed but not decrypted
- CONNECT_IND detection relies on:
  - Specific LL control opcodes
- Does not support:
  - Multiple PHYs
  - Extended advertising
  - Isochronous channels
- No live BLE interaction yet (offline only)

Intended Use Cases

BLE protocol analysis

Security research and vulnerability discovery

Educational material

Reverse engineering BLE devices

CTF challenges and training labs

License
SPDX-License-Identifier: GPL-3.0-only
Copyright (C) 2025 Kevin Leon

## Roadmap
- Live BLE device interaction
- Replay / fuzzing support
- Advanced correlation (notifications, indications)
- Decryption support