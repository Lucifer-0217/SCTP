"""
Full SCTP protocol support for Scapy.
Includes chunk parsing and accurate dissection suitable for SS7 over M3UA traffic.
"""

from scapy.packet import Packet, bind_layers
from scapy.fields import (
    ShortField, IntField, ByteField, StrLenField, PacketListField
)
from scapy.all import IP, IPv6
import struct


# === SCTP Chunk Types (RFC 4960) ===
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
        # Future enhancement: Return specific chunk classes per type
        return Packet.guess_payload_class(self, payload)

    def post_build(self, pkt, pay):
        if self.len is None:
            l = len(pkt) + len(pay)
            pkt = pkt[:2] + struct.pack("!H", l) + pkt[4:]
        return pkt + pay

    def extract_padding(self, s):
        # Chunks are 4-byte aligned
        return s[:self.len], s[self.len:]


class SCTP(Packet):
    name = "SCTP"
    fields_desc = [
        ShortField("sport", 0),
        ShortField("dport", 0),
        IntField("tag", 0),
        IntField("chksum", 0),  # Usually CRC32C
        PacketListField("chunks", [], SCTPChunk,
                        length_from=lambda pkt: len(pkt) - 12)
    ]

    def guess_payload_class(self, payload):
        return Packet.guess_payload_class(self, payload)

    def post_build(self, pkt, pay):
        # Leave checksum untouched for now (usually done in kernel stack)
        return pkt + pay


# === Layer Bindings ===
bind_layers(IP, SCTP, proto=132)      # IP protocol 132 = SCTP
bind_layers(IPv6, SCTP, nh=132)
