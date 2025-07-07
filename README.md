## 📄 `README.md` for `sctp.py`

```markdown
# SCTP Protocol Layer for Scapy (`sctp.py`)

> 💣 High-Fidelity SCTP Parsing Module for Trinetra Framework  
> 📡 Enables decoding of live telecom SS7 traffic over SCTP with precision.

---

## 📌 Purpose

The `sctp.py` module provides full **SCTP (Stream Control Transmission Protocol)** layer support for [Scapy](https://scapy.net/), enabling accurate dissection of SS7 packets transported over SCTP — such as **M3UA, SCCP, TCAP, and MAP**.

It was specifically developed for **Trinetra**, a military-grade SS7 surveillance and monitoring framework used in telecom security environments.

---

## ❓ Why We Built This

The official Scapy distribution **no longer includes `scapy.contrib.sctp`** as of 2024+. Attempts to import it result in:

```

ModuleNotFoundError: No module named 'scapy.contrib.sctp'

````

Since **SCTP is the core transport protocol for SS7** over IP networks (SIGTRAN stack), this module is mission-critical for:

- **Live traffic sniffing** from network interfaces
- **Real-time decoding** of intercepted MAP messages
- **MAP-FORWARD-SHORT-MESSAGE**, **SEND-ROUTING-INFO**, IMSI/MSC extraction, etc.

Thus, this custom `sctp.py` restores full SCTP protocol dissection capability for national security tooling.

---

## ⚙️ Features

| Feature | Description |
|--------|-------------|
| ✅ Full Chunk Parsing | Decodes all SCTP chunks (DATA, INIT, SACK, etc.) |
| ✅ Payload Extraction | 4-byte aligned chunk payloads for downstream decoding |
| ✅ IP + IPv6 Support | Works seamlessly with both IP versions |
| ✅ PacketListField | Dynamically parses variable number of chunks |
| ✅ Bindable with Scapy | Uses `bind_layers()` to integrate into Scapy's packet tree |
| ✅ Lightweight & Fast | Pure Python, no external dependencies |

---

## 🧠 How It Works

1. `SCTP` packet binds to IP/IPv6 protocol 132.
2. It extracts:
   - Source/Destination Ports
   - Verification Tag
   - Checksum (CRC32C)
   - Chunks (`SCTPChunk`)
3. Each `SCTPChunk` includes:
   - Chunk Type (e.g., 0 = DATA)
   - Flags
   - Length
   - Payload (MAP, M3UA, etc.)
4. Final chunk payload is handed off to Trinetra's `ss7_decode.py` module for deep telecom parsing.

---

## 🧩 Integration with Trinetra

`ss7_capture.py` uses this module to enable:

- 🎯 Live sniffing over `interface=Wi-Fi` or `eth0`
- 📂 PCAP offline analysis
- 🔁 Thread-safe decode queue
- 💡 Real-time telecom intelligence extraction

Simply load it with:

```python
from scapy.all import load_contrib
load_contrib("sctp")
from scapy.contrib.sctp import SCTP
````

---

## 🧪 Testing

```bash
python -c "from scapy.all import load_contrib; load_contrib('sctp'); from scapy.contrib.sctp import SCTP; print(SCTP().summary())"
```

Should return:

```
SCTP  sport=0 dport=0 tag=0 chksum=0 chunks=[]
```

---

## 🔐 Security Considerations

* Does not auto-validate checksum (for performance).
* Safe to use on live networks — no packet injection, only parsing.
* Designed for **read-only sniffing**; no network write.

---

## 🚀 Future Scope

* Per-chunk class mapping (e.g., `SCTP_INIT`, `SCTP_DATA`)
* Optional CRC32C checksum validation
* M3UA deep parser as sibling module
* SCTP multi-homing extensions (RFC 5061)

---

## 🏁 Maintained By

This module is maintained by the **Trinetra Security Team**, for use in government-grade SS7 interception systems.
Contact: `amitkasbe2709@gmail.com` (placeholder)

---

## 📂 File Location

```
/venv/Lib/site-packages/scapy/contrib/sctp.py
```

---

## ✅ License

This file is released under the same license as Scapy: **GPL v2**
Derived and extended from Scapy community codebase with additional enhancements.

```
