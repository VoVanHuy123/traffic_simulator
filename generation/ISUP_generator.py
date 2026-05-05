import time
import random
import struct
import numpy as np
import pandas as pd

from scapy.all import IP, wrpcap
# from scapy.contrib.isup import ISUP
from scapy.layers.sctp import SCTP, SCTPChunkData
# from scapy.contrib.m3ua import M3UA

from .base_generator import BaseFlowGenerator
from rules.protocol_rules import PROTOCOL_RULES


# ==============================
# ISUP MESSAGE MAP
# ==============================

ISUP_MESSAGE_CODES = {
    "IAM": 1,
    "ACM": 2,
    "ANM": 3,
    "REL": 5,
    "RLC": 6,
    "RSC": 7,
    "SAM": 12,
    "COT": 16,
}
ISUP_MESSAGE_DIRECTION = {
    "IAM": 0,
    "ACM": 1,
    "ANM": 1,
    "REL": 0,
    "RLC": 1,
    "RSC": 0,
    "SAM": 0,
    "COT": 0,
}

def normalize_msg_type(msg):
    if isinstance(msg, str):
        return ISUP_MESSAGE_CODES.get(msg.upper(), 1)
    return int(msg)


def build_isup_iam():
    msg_type = b"\x01"
    nature_conn = b"\x00"
    forward_call_ind = b"\x60\x00"
    calling_party_cat = b"\x0a"
    trans_medium_req = b"\x03"
    ptr_called = b"\x03"
    ptr_calling = b"\x00"
    ptr_optional = b"\x00"
    address_info = b"\x03\x10\x13\x12\x34\x56"
    called_party_param = struct.pack("B", len(address_info)) + address_info
    return msg_type + nature_conn + forward_call_ind + calling_party_cat + \
           trans_medium_req + ptr_called + ptr_calling + ptr_optional + called_party_param


def build_isup_acm():
    # --- 1. ISUP FIXED PART (Phần cố định) ---
    msg_type = b"\x06"                # Address Complete (6)
    backward_call_ind = b"\x01\x10" 
    ptr_optional = b"\x00"
    optional_params = b""
    return msg_type + backward_call_ind + ptr_optional + optional_params


# def build_isup_anm():
#     """Answer Message"""
#     msg_type = b"\x03"
#     optional_backward_ind = b"\x00"
#     ptr_optional = b"\x02"
#     return msg_type + optional_backward_ind + ptr_optional
def build_isup_anm():
    # --- 1. ISUP MESSAGE TYPE ---
    msg_type = b"\x09" 
    ptr_optional = b"\x00"
    optional_params = b""
    return msg_type + ptr_optional + optional_params


# def build_isup_rel():
#     """Release Message"""
#     msg_type = b"\x05"
#     cause_ind = b"\x02\x80"  # Normal Release
#     ptr_optional = b"\x03"
#     return msg_type + cause_ind + ptr_optional
def build_isup_rel():
    msg_type = b"\x0c" 
    ptr_cause = b"\x02" 
    ptr_optional = b"\x00"
    cause_param = b"\x02" + b"\x80" + b"\x90"
    return msg_type + ptr_cause + ptr_optional + cause_param

def build_isup_rlc():
    # --- 1. ISUP MESSAGE TYPE ---
    msg_type = b"\x10"             
    ptr_optional = b"\x00"
    optional_params = b""
    return msg_type + ptr_optional + optional_params

def build_isup_rsc():
    """Reset Circuit Message"""
    msg_type = b"\x07"
    return msg_type


# def build_isup_rlc():
#     """Release Complete Message"""
#     msg_type = b"\x06"
#     return msg_type


def build_isup_sam():
    """Subsequent Address Message"""
    msg_type = b"\x0c"
    called_party_info = b"\x04\x10\x98\x76\x54\x32"
    called_party_param = struct.pack("B", len(called_party_info)) + called_party_info
    return msg_type + called_party_param


def build_isup_cot():
    """Continuity Message"""
    msg_type = b"\x10"
    continuity_ind = b"\x00"
    return msg_type + continuity_ind


def build_isup_message(msg_code):
    """Build ISUP message based on numeric code"""
    # Handle numeric values
    if isinstance(msg_code, str):
        msg_code = normalize_msg_type(msg_code)
    else:
        msg_code = int(msg_code)
    
    if msg_code == ISUP_MESSAGE_CODES["IAM"]:
        return build_isup_iam()
    elif msg_code == ISUP_MESSAGE_CODES["ACM"]:
        return build_isup_acm()
    elif msg_code == ISUP_MESSAGE_CODES["ANM"]:
        return build_isup_anm()
    elif msg_code == ISUP_MESSAGE_CODES["REL"]:
        return build_isup_rel()
    elif msg_code == ISUP_MESSAGE_CODES["RLC"]:
        return build_isup_rlc()
    elif msg_code == ISUP_MESSAGE_CODES["RSC"]:
        return build_isup_rsc()
    elif msg_code == ISUP_MESSAGE_CODES["SAM"]:
        return build_isup_sam()
    elif msg_code == ISUP_MESSAGE_CODES["COT"]:
        return build_isup_cot()
    return bytes([msg_code, 0x00, 0x00, 0x00])


# ==============================
# BUILD M3UA PARAMETER
# ==============================

def build_m3ua_protocol_data(isup_bytes, opc=1, dpc=2, sls=None):
    """
    Tạo M3UA Protocol Data parameter (Tag 0x0210) bao gồm Routing Label chuẩn.
    Cấu trúc Routing Label (12 bytes):
    - OPC (32 bit)
    - DPC (32 bit)
    - SIO (8 bit): SI=5 (ISUP)
    - NI (8 bit)
    - MP (8 bit)
    - SLS (8 bit)
    """
    sio = 5  # Service Indicator: ISUP
    ni = 0   # Network Indicator
    mp = 0   # Message Priority
    if sls is None:
        sls = random.randint(0, 15)

    routing_label = struct.pack(
        "!II4B",
        opc,
        dpc,
        sio,
        ni,
        mp,
        sls
    )
    
    payload = routing_label + isup_bytes

    # ---- M3UA Protocol Data parameter manual build ----
    tag = 0x0210
    param_length = 4 + len(payload)
    pad_len = (4 - (param_length % 4)) % 4
    
    param_header = struct.pack("!HH", tag, param_length)
    param = param_header + payload
    
    if pad_len:
        param += b"\x00" * pad_len

    return param


# ==============================
# GENERATOR
# ==============================

class ISUPFlowGenerator(BaseFlowGenerator):

    protocol = "isup"

    def decode_packet(self, parts):
        msg_type = parts[0]
        direction = int(parts[1])
        length_bin = int(parts[2])
        iat_bin = int(parts[3])

        length_map = {
            0: np.random.randint(14, 20),
            1: np.random.randint(20, 30),
            2: np.random.randint(30, 40),
        }

        iat_map = {
            0: np.random.uniform(0.0001, 0.01),
            1: np.random.uniform(0.01, 0.1),
            2: np.random.uniform(0.1, 0.5),
        }

        return {
            "direction": direction,
            "isup_msg_type": str(msg_type),
            "packet_length": length_map.get(length_bin, 20),
            "iat": iat_map.get(iat_bin, 0.01),
        }

    def build_packet(self, src_ip, dst_ip, msg_type, cic ,opc=1, dpc=2):
        msg_code = normalize_msg_type(msg_type)

        

        # ---------------- ISUP ----------------
        isup_body = build_isup_message(msg_code)
        cic_bytes = struct.pack("<H", cic)

        # ---------------- M3UA Protocol Data ----------------
        m3ua_payload = build_m3ua_protocol_data(cic_bytes + isup_body, opc=opc, dpc=dpc, sls=cic & 0x0F)

        # ---------------- M3UA Header ----------------
        m3ua_header = b"\x01\x00\x01\x01" + struct.pack("!I", len(m3ua_payload) + 8)
        m3ua_bytes = m3ua_header + m3ua_payload

        # ---------------- SCTP ----------------
        pkt = (
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

        return pkt

    # def to_pcap(self, flows, output="isup_generated.pcap"):
    #     packets = []
    #     now = time.time()
        

    #     if isinstance(flows, pd.DataFrame):
    #         flows = [flows]

    #     for df in flows:
    #         client_ip = f"192.0.2.{random.randint(2,200)}"
    #         server_ip = f"198.51.100.{random.randint(2,200)}"
    #         cic = random.randint(1, 60)
    #         opc_tmp = random.randint(1, 100)
    #         dpc_tmp = random.randint(1, 100)
        

    #         for _, row in df.iterrows():
    #             direction = int(row["direction"])
    #             msg_type = row["isup_msg_type"]
    #             iat = float(row["iat"])

    #             if ISUP_MESSAGE_DIRECTION.get(msg_type.upper(), 0) == 0:
    #                 opc = opc_tmp
    #                 dpc = dpc_tmp
    #             else:
    #                 opc = dpc_tmp
    #                 dpc = opc_tmp

    #             now += iat

    #             src = client_ip if direction == 0 else server_ip
    #             dst = server_ip if direction == 0 else client_ip

    #             pkt = self.build_packet(src, dst, msg_type,cic,opc,dpc)
    #             pkt.time = now

    #             packets.append(pkt)

    #     wrpcap(output, packets)
    #     print(f"\n✅ Saved {len(packets)} packets -> {output}")
    def to_pcap(self, flows, output="isup_generated.pcap"):
        packets = []
        start_time = time.time()

        if isinstance(flows, pd.DataFrame):
            flows = [flows]

        # ==============================
        # INIT FLOW STATES
        # ==============================
        flow_states = []

        for i,df in enumerate(flows):
            flow_states.append({
                "df": df.reset_index(drop=True),
                "idx": 0,
                "cic": random.randint(1, 60),
                "opc_tmp": random.randint(1, 100),
                "dpc_tmp": random.randint(1, 100),
                "time": start_time + i * random.uniform(0.1, 0.5),
                "client_ip": f"192.0.2.{random.randint(2,200)}",
                "server_ip": f"198.51.100.{random.randint(2,200)}"
            })

        active_flows = flow_states.copy()

        # ==============================
        # INTERLEAVE
        # ==============================
        while active_flows:
            i = random.randrange(len(active_flows))
            flow = active_flows[i]

            if flow["idx"] >= len(flow["df"]):
                active_flows.pop(i)
                continue

            row = flow["df"].iloc[flow["idx"]]
            flow["idx"] += 1

            direction = int(row["direction"])
            msg_type = row["isup_msg_type"]
            iat = float(row["iat"])

            # 👉 OPC / DPC theo direction ISUP
            if ISUP_MESSAGE_DIRECTION.get(msg_type.upper(), 0) == 0:
                opc = flow["opc_tmp"]
                dpc = flow["dpc_tmp"]
            else:
                opc = flow["dpc_tmp"]
                dpc = flow["opc_tmp"]

            flow["time"] += iat

            src = flow["client_ip"] if direction == 0 else flow["server_ip"]
            dst = flow["server_ip"] if direction == 0 else flow["client_ip"]

            pkt = self.build_packet(
                src,
                dst,
                msg_type,
                flow["cic"],
                opc,
                dpc
            )

            pkt.time = flow["time"]
            packets.append(pkt)

        # 👉 rất quan trọng
        packets.sort(key=lambda x: x.time)

        wrpcap(output, packets)
        print(f"\n✅ Saved {len(packets)} packets -> {output}")

    def generate_sequences_by_stages(self, pkt_count):
        """
        Sinh sequences packet ISUP theo các giai đoạn: setup, active, cleanup
        Trả về tuple: (DataFrame tổng hợp, dict các giai đoạn)
        """
        rules = PROTOCOL_RULES.get(self.protocol)
        stages = rules.get("stages")
        stage_pkts = rules.get("stage_packets")

        results = []
        results_dict = {
            "setup": None,
            "active": None,
            "cleanup": None
        }
        remaining = pkt_count

        # 1. SETUP
        setup_count = stage_pkts.get("setup", 2)
        if remaining >= setup_count:
            self.set_model("setup")
            df = self.generate(setup_count)
            results.append(df)
            results_dict["setup"] = df
            remaining -= setup_count
        else:
            
            self.set_model("setup")
            df = self.generate(remaining)
            results.append(df)
            results_dict["setup"] = df
            return pd.concat(results, ignore_index=True), results_dict

        # 2. ACTIVE
        cleanup_count = stage_pkts.get("cleanup", 2)
        has_active = False
        if remaining > 0:
            if remaining > cleanup_count:
                active_count = remaining - cleanup_count
            else:
                active_count = remaining

            if active_count > 0:
                self.set_model("active")
                df = self.generate(active_count)
                results.append(df)
                results_dict["active"] = df
                remaining -= active_count
                has_active = True

        # 3. CLEANUP 
        if has_active and remaining > 0:
            self.set_model("cleanup")
            df = self.generate(remaining)
            results.append(df)
            results_dict["cleanup"] = df

        return pd.concat(results, ignore_index=True), results_dict
