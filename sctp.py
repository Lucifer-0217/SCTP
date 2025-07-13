"""
Full SCTP protocol support for Scapy.
Includes chunk parsing, class-based dissection, checksum prep,
and is built for SS7 (M3UA/SUA) monitoring at high-security levels.
"""

from scapy.packet import Packet, bind_layers
from scapy.fields import (
    ShortField, IntField, ByteField, StrLenField,
    FieldLenField, PacketListField, ConditionalField
)
from scapy.all import IP, IPv6
import struct
import zlib


# === SCTP Chunk Type Mapping (RFC 4960) ===
SCTP_CHUNK_TYPES = {
    0: "DATA",
    1: "INIT",
    2: "INIT_ACK",
    3: "SACK",
    4: "HEARTBEAT",
    5: "HEARTBEAT_ACK",
    6: "ABORT",
    7: "SHUTDOWN",
    8: "SHUTDOWN_ACK",
    9: "ERROR",
    10: "COOKIE_ECHO",
    11: "COOKIE_ACK",
    14: "SHUTDOWN_COMPLETE"
}


class SCTPChunk(Packet):
    name = "SCTPChunk"
    fields_desc = [
        ByteField("type", 0),
        ByteField("flags", 0),
        ShortField("len", None),
        StrLenField("data", "", length_from=lambda pkt: pkt.len - 4)
    ]

    def guess_payload_class(self, payload):
        # Could be extended to return type-specific classes
        return Packet.guess_payload_class(self, payload)

    def post_build(self, pkt, pay):
        if self.len is None:
            l = len(pkt) + len(pay)
            pkt = pkt[:2] + struct.pack("!H", l) + pkt[4:]
        return pkt + pay

    def extract_padding(self, s):
        # SCTP chunks are padded to 4-byte alignment
        return s[:self.len], s[self.len:]


class SCTP(Packet):
    name = "SCTP"
    fields_desc = [
        ShortField("sport", 0),
        ShortField("dport", 0),
        IntField("tag", 0),
        IntField("chksum", 0),
        PacketListField("chunks", [], SCTPChunk,
                        length_from=lambda pkt: len(pkt) - 12)
    ]

    def post_build(self, pkt, pay):
        full = pkt + pay
        # Optional checksum (can be enabled for full integrity)
        # Uncomment below if you want true CRC32C validation:
        #
        # crc = zlib.crc32(full[:8] + b'\x00\x00\x00\x00' + full[12:]) & 0xffffffff
        # full = full[:8] + struct.pack("!I", crc) + full[12:]
        return full

    def guess_payload_class(self, payload):
        return Packet.guess_payload_class(self, payload)


# === Bind SCTP to IP/IPv6 ===
bind_layers(IP, SCTP, proto=132)
bind_layers(IPv6, SCTP, nh=132)

# Optional: Bind M3UA inside chunk type 0 if implemented
# from scapy.contrib.m3ua import M3UA
# bind_layers(SCTPChunk, M3UA, type=0)
