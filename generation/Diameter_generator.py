import random
import struct

import numpy as np
from scapy.all import IP
from scapy.layers.sctp import SCTP, SCTPChunkData

from .base_generator import BaseFlowGenerator

# Diameter S6a Update-Location command code (3GPP TS 29.272) and flags
# (RFC 6733 sec 3): R=Request, P=Proxyable.
ULR_COMMAND_CODE = 316
APPLICATION_ID_S6A = 16777251

DIAMETER_FLAGS = {
    "ULR": 0xC0,  # Request + Proxyable
    "ULA": 0x40,  # Proxyable (Answer)
}

# AVP code 264 = Origin-Host (RFC 6733 sec 6.3), used here purely as a
# well-formed filler AVP so the message parses cleanly -- not a claim of
# full 3GPP AVP compliance (no Session-Id/Origin-Realm/etc).
ORIGIN_HOST_AVP_CODE = 264
AVP_HEADER_SIZE = 8  # code(4) + flags(1) + length(3), no vendor-id
DIAMETER_HEADER_SIZE = 20


def build_diameter_header(msg_type, hop_by_hop, end_to_end, message_length):
    version = 1
    flags = DIAMETER_FLAGS.get(msg_type, 0x00)

    return (
        struct.pack("B", version)
        + message_length.to_bytes(3, "big")
        + struct.pack("B", flags)
        + ULR_COMMAND_CODE.to_bytes(3, "big")
        + struct.pack("!I", APPLICATION_ID_S6A)
        + struct.pack("!I", hop_by_hop)
        + struct.pack("!I", end_to_end)
    )


def build_diameter_avp(code, data, flags=0x40):
    """One Diameter AVP (RFC 6733 sec 4.1): header + data, padded to a
    4-byte boundary. `AVP Length` covers header+data but NOT the padding."""
    avp_length = AVP_HEADER_SIZE + len(data)
    header = struct.pack("!I", code) + struct.pack("B", flags) + avp_length.to_bytes(3, "big")
    avp = header + data
    pad_len = (4 - (len(avp) % 4)) % 4
    return avp + b"\x00" * pad_len


class DiameterFlowGenerator(BaseFlowGenerator):
    protocol = "diameter"

    def build_packets(self, all_df, base_time):
        packets = []
        time = base_time

        for df in all_df:
            mme_ip = f"10.30.0.{np.random.randint(2, 200)}"
            hss_ip = f"10.40.0.{np.random.randint(2, 200)}"
            hop_by_hop = random.randint(1, 2**32 - 1)
            end_to_end = random.randint(1, 2**32 - 1)

            for row in df.to_dict("records"):
                time += float(row["iat"])

                direction = int(row["direction"])
                msg_type = str(row["diameter_cmd"])
                pkt_len = int(row["packet_length"])

                if direction == 0:
                    src, dst = mme_ip, hss_ip
                else:
                    src, dst = hss_ip, mme_ip

                # Fill the gap between the fixed 20-byte header and the
                # declared packet_length with one real, well-formed AVP
                # (Origin-Host) instead of raw padding -- raw zero bytes
                # after the header don't parse as a valid AVP, which is what
                # was still triggering [Malformed Packet] even after the
                # message-length field itself was fixed.
                avp_data_len = max(1, pkt_len - DIAMETER_HEADER_SIZE - AVP_HEADER_SIZE)
                hostname = f"mme{random.randint(1, 999)}.epc.mnc001.mcc001.3gppnetwork.org".encode()
                avp_data = (hostname * (avp_data_len // len(hostname) + 1))[:avp_data_len]
                avp = build_diameter_avp(ORIGIN_HOST_AVP_CODE, avp_data)

                total_length = DIAMETER_HEADER_SIZE + len(avp)
                header = build_diameter_header(msg_type, hop_by_hop, end_to_end, total_length)

                pkt = (
                    IP(src=src, dst=dst)
                    / SCTP(sport=3868, dport=3868)
                    / SCTPChunkData(
                        proto_id=0,
                        stream_id=0,
                        tsn=random.randint(1, 2**31),
                        beginning=1,
                        ending=1,
                        data=header + avp,
                    )
                )
                pkt.time = time
                packets.append(pkt)

        return packets
