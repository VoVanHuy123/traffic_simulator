import random
import struct

import numpy as np
from scapy.all import IP
from scapy.layers.sctp import SCTP, SCTPChunkData

from .base_generator import BaseFlowGenerator

# Simplified (non-ASN.1-strict) MAP operation codes, enough to distinguish
# message types on the wire -- mirrors the level of approximation
# generation/ISUP_generator.py already uses for its message bodies.
MAP_OPERATION_CODES = {
    "UPDATE_LOCATION": 2,
    "INSERT_SUBSCRIBER_DATA": 7,
    "INSERT_SUBSCRIBER_DATA_ACK": 107,
    "UPDATE_LOCATION_ACK": 102,
}

# TCAP package type: Begin for the first invoke of a dialogue, End for the
# final response, Continue for everything in between.
TCAP_BEGIN = 0x62
TCAP_CONTINUE = 0x65
TCAP_END = 0x64


def build_map_message(msg_type, invoke_id):
    opcode = MAP_OPERATION_CODES.get(msg_type, 0)

    if msg_type == "UPDATE_LOCATION":
        tcap_tag = TCAP_BEGIN
    elif msg_type == "UPDATE_LOCATION_ACK":
        tcap_tag = TCAP_END
    else:
        tcap_tag = TCAP_CONTINUE

    component = struct.pack("BB", opcode, invoke_id & 0xFF)
    return struct.pack("B", tcap_tag) + component


def build_m3ua_protocol_data(payload, opc=1, dpc=2, sls=None):
    """Same simplified M3UA Protocol Data (tag 0x0210) construction as
    generation/ISUP_generator.py, but with SIO=3 (SCCP) since MAP/TCAP rides
    over SCCP, not directly over ISUP's SIO=5."""
    sio = 3  # Service Indicator: SCCP
    ni = 0
    mp = 0
    if sls is None:
        sls = random.randint(0, 15)

    routing_label = struct.pack("!II4B", opc, dpc, sio, ni, mp, sls)
    body = routing_label + payload

    tag = 0x0210
    param_length = 4 + len(body)
    pad_len = (4 - (param_length % 4)) % 4

    param = struct.pack("!HH", tag, param_length) + body
    if pad_len:
        param += b"\x00" * pad_len
    return param


class MAPFlowGenerator(BaseFlowGenerator):
    protocol = "map"

    def build_packet(self, src_ip, dst_ip, msg_type, invoke_id, opc=1, dpc=2):
        map_bytes = build_map_message(msg_type, invoke_id)
        m3ua_payload = build_m3ua_protocol_data(map_bytes, opc=opc, dpc=dpc)
        m3ua_header = b"\x01\x00\x01\x01" + struct.pack("!I", len(m3ua_payload) + 8)
        m3ua_bytes = m3ua_header + m3ua_payload

        return (
            IP(src=src_ip, dst=dst_ip)
            / SCTP(sport=2905, dport=2905)
            / SCTPChunkData(
                proto_id=3,  # M3UA
                stream_id=1,
                tsn=random.randint(1, 2**31),
                beginning=1,
                ending=1,
                data=m3ua_bytes,
            )
        )

    def build_packets(self, all_df, base_time):
        packets = []
        time = base_time

        for df in all_df:
            vlr_ip = f"10.10.0.{np.random.randint(2, 200)}"
            hlr_ip = f"10.20.0.{np.random.randint(2, 200)}"
            opc_tmp = random.randint(1, 100)
            dpc_tmp = random.randint(1, 100)
            invoke_id = random.randint(1, 127)

            for row in df.to_dict("records"):
                time += float(row["iat"])

                direction = int(row["direction"])
                msg_type = str(row["map_msg_type"])

                if direction == 0:
                    src, dst = vlr_ip, hlr_ip
                    opc, dpc = opc_tmp, dpc_tmp
                else:
                    src, dst = hlr_ip, vlr_ip
                    opc, dpc = dpc_tmp, opc_tmp

                pkt = self.build_packet(src, dst, msg_type, invoke_id, opc, dpc)
                pkt.time = time
                packets.append(pkt)

        return packets
