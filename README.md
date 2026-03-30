# SCTP — Full Protocol Support for Scapy

> **Developed by Amit Kasbe**
> A high-fidelity, pure-Python SCTP (Stream Control Transmission Protocol) dissection layer for Scapy, engineered for telecom protocol surveillance, SS7 signal analysis, and SIGTRAN stack decoding.

[![Python Package](https://github.com/amitkasbe/SCTP/actions/workflows/python-package.yml/badge.svg)](https://github.com/amitkasbe/SCTP/actions/workflows/python-package.yml)
[![Python Versions](https://img.shields.io/badge/python-3.9%20|%203.10%20|%203.11-blue)](https://www.python.org/)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)

---

## Table of Contents

- [Overview](#overview)
- [Background](#background)
- [Features](#features)
- [Architecture](#architecture)
- [Protocol Dissection Workflow](#protocol-dissection-workflow)
- [Installation](#installation)
- [Usage](#usage)
- [Supported Chunk Types](#supported-chunk-types)
- [Operational Use Cases](#operational-use-cases)
- [Security Profile](#security-profile)
- [CI/CD Pipeline](#cicd-pipeline)
- [Future Enhancements](#future-enhancements)
- [License](#license)
- [Author](#author)

---

## Overview

`sctp.py` is a full-featured SCTP protocol dissection module for [Scapy](https://scapy.net/), the powerful Python-based interactive packet manipulation library. It provides class-based parsing, chunk-level dissection, checksum handling, and seamless layer binding to IPv4 and IPv6 — making it an indispensable tool for anyone working at the telecom or SIGTRAN protocol stack layer.

The module is designed with a focus on **SS7 (Signaling System 7) monitoring** at high-security levels, where SCTP is the mandatory transport layer beneath protocols such as M3UA, SUA, SCCP, TCAP, and MAP.

---

## Background

SCTP (Stream Control Transmission Protocol) is defined in [RFC 4960](https://www.rfc-editor.org/rfc/rfc4960) and serves as the transport backbone for most modern telecom signaling infrastructure. Unlike TCP or UDP, SCTP is a message-oriented, multi-stream protocol that supports multi-homing — qualities that make it essential in carrier-grade networks.

Without a proper SCTP dissection layer, upstream decoding of the full SS7 protocol chain (MAP/TCAP/SCCP/M3UA) becomes impossible. This module bridges that gap by providing a clean, bindable implementation that integrates naturally with Scapy's layered packet model.

---

## Features

| Capability | Description |
|---|---|
| ✅ SCTP Header Parsing | Decodes source port, destination port, verification tag, and CRC32C checksum fields |
| ✅ Chunk Support | Full dissection of INIT, DATA, ABORT, SACK, HEARTBEAT, and all RFC 4960 chunk types |
| ✅ 4-Byte Alignment | Enforces the SCTP padding alignment requirement for clean telecom stack dissection |
| ✅ Multi-Chunk Field | Uses Scapy's `PacketListField` for dynamic, sequential chunk parsing within a single packet |
| ✅ Scapy Integration | Layer-bound to `IP` and `IPv6` via `bind_layers()` using IANA protocol number `132` |
| ✅ SIGTRAN-Ready | Structured to hand off payloads to M3UA, SCCP, TCAP, and MAP parsers |
| ✅ CRC32C Support | Checksum computation via `zlib` (optional, toggled for performance) |
| ✅ Lightweight | Pure Python — zero native libraries or C extensions required |
| ✅ IPv4 & IPv6 | Dual-stack support for both modern and legacy network environments |

---

## Architecture

The module is composed of two primary classes and a chunk-type registry:

### `SCTP_CHUNK_TYPES` — Chunk Type Registry

A dictionary mapping numeric chunk type identifiers (per RFC 4960) to their human-readable names. This registry drives chunk classification during dissection.

```
0  → DATA            7  → SHUTDOWN
1  → INIT            8  → SHUTDOWN_ACK
2  → INIT_ACK        9  → ERROR
3  → SACK           10  → COOKIE_ECHO
4  → HEARTBEAT      11  → COOKIE_ACK
5  → HEARTBEAT_ACK  14  → SHUTDOWN_COMPLETE
6  → ABORT
```

---

### `SCTPChunk` — Chunk-Level Dissector

Inherits from `scapy.packet.Packet`. Represents a single SCTP chunk within the chunks list of an SCTP packet.

**Fields:**

| Field | Type | Description |
|---|---|---|
| `type` | `ByteField` | Chunk type identifier (see `SCTP_CHUNK_TYPES`) |
| `flags` | `ByteField` | Chunk-specific flags byte |
| `len` | `ShortField` | Total chunk length in bytes, including the 4-byte header |
| `data` | `StrLenField` | Raw chunk payload, length derived from `len - 4` |

**Key Methods:**

- `post_build()` — Auto-calculates the `len` field if not explicitly set, ensuring correct wire-format encoding.
- `extract_padding()` — Strips 4-byte boundary padding from the stream, preventing misalignment when parsing multiple consecutive chunks.

---

### `SCTP` — Main SCTP Header Dissector

Inherits from `scapy.packet.Packet`. Represents the SCTP common header.

**Fields:**

| Field | Type | Description |
|---|---|---|
| `sport` | `ShortField` | Source port (16-bit) |
| `dport` | `ShortField` | Destination port (16-bit) |
| `tag` | `IntField` | Verification tag (32-bit) — used for association identification |
| `chksum` | `IntField` | CRC32C checksum (32-bit) |
| `chunks` | `PacketListField` | Ordered list of `SCTPChunk` objects parsed from the packet body |

**Key Methods:**

- `post_build()` — Provides an optional CRC32C checksum computation hook over the full packet. Disabled by default for performance; can be activated by uncommenting the relevant block.

---

### Layer Bindings

```python
bind_layers(IP,   SCTP, proto=132)
bind_layers(IPv6, SCTP, nh=132)
```

These bindings register SCTP as the payload class for IP and IPv6 packets carrying protocol/next-header value `132`, enabling Scapy's automatic dissection engine to recognize and parse SCTP transparently.

---

## Protocol Dissection Workflow

```
Raw Packet (Ethernet Frame)
       │
       ▼
  IP / IPv6 Header
  (proto=132 / nh=132)
       │
       ▼
  SCTP Common Header
  ┌────────┬────────┬─────────┬──────────┐
  │ sport  │ dport  │   tag   │  chksum  │
  └────────┴────────┴─────────┴──────────┘
       │
       ▼
  SCTPChunk List (PacketListField)
  ┌───────────────────────────────────┐
  │ type │ flags │  len  │  payload  │  ← Chunk 1 (e.g., INIT)
  └───────────────────────────────────┘
  ┌───────────────────────────────────┐
  │ type │ flags │  len  │  payload  │  ← Chunk 2 (e.g., DATA)
  └───────────────────────────────────┘
       │
       ▼
  Payload Handoff
  ┌──────────────────────────────────────┐
  │  ss7_decode.py  →  M3UA / SCCP /    │
  │                    TCAP / MAP        │
  └──────────────────────────────────────┘
```

Each SCTP chunk payload is extracted and forwarded downstream to the appropriate SIGTRAN or SS7 protocol decoder, enabling full end-to-end decoding of telecom signaling traffic.

---

## Installation

### Prerequisites

- Python 3.9, 3.10, or 3.11
- [Scapy](https://scapy.net/) installed in your environment

```bash
pip install scapy
```

### Deployment

Place `sctp.py` in Scapy's contrib directory:

```bash
<your-venv>/lib/pythonX.X/site-packages/scapy/contrib/sctp.py
```

You may need elevated permissions depending on your environment. For repeatable deployment in CI/CD pipelines or toolchain provisioning, consider automating this path placement in a setup script.

---

## Usage

### Basic Instantiation

```python
from scapy.all import load_contrib
load_contrib("sctp")

from scapy.contrib.sctp import SCTP, SCTPChunk

pkt = SCTP()
print(pkt.summary())
# Output: SCTP  sport=0 dport=0 tag=0 chksum=0 chunks=[]
```

### Building a Packet with Chunks

```python
from scapy.all import IP
from scapy.contrib.sctp import SCTP, SCTPChunk

# Build an SCTP INIT packet
chunk = SCTPChunk(type=1, flags=0)   # type=1 → INIT
pkt = IP(dst="192.168.1.1") / SCTP(sport=2905, dport=2905, tag=12345) / chunk

pkt.show()
```

### Dissecting a Raw Capture

```python
from scapy.all import rdpcap
from scapy.contrib.sctp import SCTP

packets = rdpcap("capture.pcap")
for pkt in packets:
    if SCTP in pkt:
        sctp_layer = pkt[SCTP]
        print(f"sport={sctp_layer.sport} dport={sctp_layer.dport}")
        for chunk in sctp_layer.chunks:
            print(f"  Chunk type={chunk.type} len={chunk.len}")
```

### Live Sniffing

```python
from scapy.all import sniff
from scapy.contrib.sctp import SCTP

def handle(pkt):
    if SCTP in pkt:
        print(pkt[SCTP].summary())

sniff(iface="eth0", prn=handle, filter="sctp", store=False)
```

---

## Supported Chunk Types

All chunk types defined in RFC 4960 are registered in `SCTP_CHUNK_TYPES`:

| Code | Chunk Type | Description |
|---|---|---|
| 0 | DATA | User data transfer |
| 1 | INIT | Association initiation |
| 2 | INIT_ACK | Initiation acknowledgment |
| 3 | SACK | Selective acknowledgment |
| 4 | HEARTBEAT | Path liveness check |
| 5 | HEARTBEAT_ACK | Heartbeat acknowledgment |
| 6 | ABORT | Association abort |
| 7 | SHUTDOWN | Graceful shutdown request |
| 8 | SHUTDOWN_ACK | Shutdown acknowledgment |
| 9 | ERROR | Operation error |
| 10 | COOKIE_ECHO | State cookie |
| 11 | COOKIE_ACK | Cookie acknowledgment |
| 14 | SHUTDOWN_COMPLETE | Shutdown complete |

---

## Operational Use Cases

This module is designed to power components in SIGTRAN/SS7 monitoring systems. Primary use cases include:

**Live Packet Sniffing**
Capture SCTP traffic in real time from network interfaces (`eth0`, `any`, `mon0`) for inline protocol analysis and alerting.

**Offline PCAP Analysis**
Parse stored packet captures in chain-of-custody environments for forensic investigation or compliance auditing.

**SS7 Threat Detection**
Feed decoded SCTP payloads into SS7 analyzers to detect:
- Fake MSC/HLR location lookups
- MAP-FORWARD-SHORT-MESSAGE abuse (SMS interception)
- IMSI harvesting via SEND-ROUTING-INFO queries
- Unauthorized subscriber tracking

**SIGTRAN Stack Decoding**
Act as the transport layer for decoding M3UA, SUA, SCCP, TCAP, and MAP protocols in end-to-end signaling chains.

---

## Security Profile

| Attribute | Status |
|---|---|
| Write-safe | ✅ Module only reads/sniffs — no packet injection support |
| Injection-safe | ✅ No active transmission capability |
| Checksum validation | 🔧 Optional CRC32C (available, disabled by default) |
| Error resilience | ✅ Graceful handling of malformed or truncated chunks |
| Logging compatibility | ✅ Compatible with external `logger.py` and `alerts.py` modules |

---

## CI/CD Pipeline

The repository includes a GitHub Actions workflow (`.github/workflows/python-package.yml`) that runs on every push and pull request to `main`.

**Matrix:** Python 3.9, 3.10, 3.11 on `ubuntu-latest`

**Steps:**

1. **Checkout** — Retrieves the repository source.
2. **Setup Python** — Configures the target Python version.
3. **Install dependencies** — Upgrades pip; installs `flake8` and `pytest`; installs from `requirements.txt` if present.
4. **Lint with flake8** — Enforces syntax correctness (errors: E9, F63, F7, F82) and style compliance (max line length 127, max complexity 10).
5. **Test with pytest** — Executes the full test suite.

---

## Future Enhancements

- **Per-chunk class dissectors** — Dedicated `SCTP_DATA`, `SCTP_INIT`, `SCTP_SACK` Packet subclasses for field-level access to chunk parameters.
- **CRC32C validation on demand** — Toggle-able checksum verification for integrity-sensitive environments.
- **Native M3UA decoder** — Decode Routing Context, Protocol Data, and Network Appearance fields directly.
- **SCTP multi-homing support** — Handle address parameters per RFC 5061 for multi-homed association dissection.
- **Type-specific payload dispatch** — `guess_payload_class()` routing by chunk type to enable automatic layering of upper-protocol parsers.

---

## License

This module is distributed under the **GNU General Public License v2.0**. It is a derivative of Scapy's original SCTP contribution, with further extensions for telecom protocol analysis.

```
This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
```

See the [GNU GPL v2 full text](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html) for complete terms.

---

## Author

**Amit Kasbe**

---

*Built for precision protocol analysis in high-security telecom environments.*
