
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from scapy.all import rdpcap, ARP, ICMP, IP, IPv6, TCP, UDP, BOOTP
import csv
import numpy as np
from collections import defaultdict
from scapy.all import *
from rules.protocol_rules import PROTOCOL_RULES



# -----------------------------
# Detect application protocol
# -----------------------------
def detect_protocol(pkt):

    if pkt.haslayer(TCP):

        sport = pkt[TCP].sport
        dport = pkt[TCP].dport

        if sport == 80 or dport == 80:
            return "HTTP"

        if sport == 443 or dport == 443:
            return "HTTPS"

        if sport == 53 or dport == 53:
            return "DNS"

        return "TCP"

    elif pkt.haslayer(UDP):

        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

        if sport == 53 or dport == 53:
            return "DNS"

        if sport == 67 or dport == 68:
            return "DHCP"

        return "UDP"
    elif pkt.haslayer(ICMP):

        return "ICMP"

    return "OTHER"

def extract_packet_fields(pkt):

    data = {
        "src_ip": None,
        "dst_ip": None,
        "src_port": 0,
        "dst_port": 0,
        "transport": None,
        "protocol": None,
        "xid": None,
        "id": None,
        "icmp_id": None
    }

    # DHCP
    if pkt.haslayer(BOOTP):
        data.update({
            "protocol": "dhcp",
            "xid": pkt[BOOTP].xid
        })

    # ARP
    elif pkt.haslayer(ARP):
        data.update({
            "src_ip": pkt[ARP].psrc,
            "dst_ip": pkt[ARP].pdst,
            "transport": "ARP",
            "protocol": "arp"
        })
    
    # IP
    elif pkt.haslayer(IP):
        ip = pkt[IP]

        data["src_ip"] = ip.src
        data["dst_ip"] = ip.dst

        if pkt.haslayer(TCP):
            data.update({
                "src_port": pkt[TCP].sport,
                "dst_port": pkt[TCP].dport,
                "transport": "TCP"
            })

        elif pkt.haslayer(UDP):
            data.update({
                "src_port": pkt[UDP].sport,
                "dst_port": pkt[UDP].dport,
                "transport": "UDP"
            })

        elif pkt.haslayer(ICMP):
            data.update({
                "transport": "ICMP",
                "protocol": "icmp",
                "icmp_id": pkt[ICMP].id
            })

        data["protocol"] = data["protocol"] or detect_protocol(pkt).lower()

        if pkt.haslayer("DNS"):
            data["id"] = pkt["DNS"].id

    return data

def normalize_flow_key(data):

    ip1 = data["src_ip"]
    ip2 = data["dst_ip"]
    p1 = data["src_port"]
    p2 = data["dst_port"]

    if (ip1, p1) <= (ip2, p2):
        return (ip1, ip2), (p1, p2)
    else:
        return (ip2, ip1), (p2, p1)
    
def build_flow_key(data):

    proto = data["protocol"]

    if proto not in PROTOCOL_RULES:
        return None
    
    if proto == "arp":

        ip1 = data["src_ip"]
        ip2 = data["dst_ip"]

        ip_pair = tuple(sorted([ip1, ip2]))

        return (
            proto,
            ip_pair
        )

    if proto in ["http", "tcp","https"]:

        ip_pair, port_pair = normalize_flow_key(data)

        return (
            proto,
            ip_pair,
            port_pair,
            data["transport"]
        )
    if proto == "dns":

        ip_pair, port_pair = normalize_flow_key(data)

        return (
            proto,
            ip_pair,
            port_pair,
            data.get("id")  
        )
    
    if proto == "dhcp":
        return (
            proto,
            data["xid"]
        )
    if proto == "icmp":
        ip1 = data["src_ip"]
        ip2 = data["dst_ip"]

        ip_pair = tuple(sorted([ip1, ip2]))
        return (
            proto,
            ip_pair,
            data["icmp_id"]
        )

    key = tuple(data[f] for f in PROTOCOL_RULES[proto]["flow_key"])

    return (proto,) + key

def get_session_start(pkt, protocol):

    # DHCP
    if protocol == "dhcp" and pkt.haslayer("DHCP"):
        for opt in pkt["DHCP"].options:
            if isinstance(opt, tuple) and opt[0] == "message-type":
                return int(opt[1]) == 1  # Discover

    # DNS
    if protocol == "dns" and pkt.haslayer("DNS"):
        return pkt["DNS"].qr == 0  # query

    # ICMP
    if protocol == "icmp" and pkt.haslayer(ICMP):
        return pkt[ICMP].type == 8  # request

    # TCP
    if protocol == "http" and pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        return (flags & 0x02) and not (flags & 0x10)

    # ARP
    if protocol == "arp" and pkt.haslayer(ARP):
        return pkt[ARP].op == 1  # request

    return False

def build_flows(input_pcap):

    packets = rdpcap(input_pcap)
    packets = sorted(packets, key=lambda x: x.time)

    flows = []
    active_sessions = {}

    for pkt in packets:

        data = extract_packet_fields(pkt)
        proto = data["protocol"]

        if proto not in PROTOCOL_RULES:
            continue

        base_key = build_flow_key(data)
        if base_key is None:
            continue

        is_start = get_session_start(pkt, proto)

        if is_start or base_key not in active_sessions:
            flow_obj = {
                "protocol": proto,
                "key_dict": data,
                "packets": []
            }

            active_sessions[base_key] = flow_obj
            flows.append(flow_obj)

        active_sessions[base_key]["packets"].append(pkt)

    return flows


def validate_protocol_flow(flow, rules):

    proto = flow["protocol"]
    packets = flow["packets"]

    # -------------------------
    # DHCP
    # -------------------------
    if proto == "dhcp":

        states = []

        for pkt in packets:
            if pkt.haslayer("DHCP"):
                for opt in pkt["DHCP"].options:
                    if isinstance(opt, tuple) and opt[0] == "message-type":
                        states.append(opt[1])

        required = rules.get("required_states", [])

        return all(s in states for s in required)

    # -------------------------
    # DNS
    # -------------------------
    elif proto == "dns":

        ids = {}

        for pkt in packets:
            if pkt.haslayer("DNS"):
                dns = pkt["DNS"]
                if dns.id not in ids:
                    ids[dns.id] = {"q": False, "r": False}

                if dns.qr == 0:
                    ids[dns.id]["q"] = True
                else:
                    ids[dns.id]["r"] = True

        return any(v["q"] and v["r"] for v in ids.values())

    # -------------------------
    # ICMP
    # -------------------------
    elif proto == "icmp":

        has_req = False
        has_rep = False

        for pkt in packets:
            if pkt.haslayer(ICMP):
                if pkt[ICMP].type == 8:
                    has_req = True
                elif pkt[ICMP].type == 0:
                    has_rep = True

        return has_req and has_rep

    # -------------------------
    # TCP (optional basic rule)
    # -------------------------
    elif proto in ["http", "https", "tcp"]:

        max_packets = PROTOCOL_RULES[proto].get("max_packets", 50)
        if len(packets) > max_packets:
            packets = packets[:max_packets]
            flow["packets"] = packets
        #ALTERNATIVE SPLIT FLOW

        first_pkt = packets[0]

        if first_pkt.haslayer("TCP"):
            flags = first_pkt["TCP"].flags

            #have to start with SYN
            if not ((flags & 0x02) and not (flags & 0x10)):
                return False

        

    return True

def clean_flows(flows):

    cleaned = []

    for flow in flows:

        packets = flow["packets"]

        # -------------------------
        # Basic check
        # -------------------------
        if len(packets) < 2:
            continue

        packets = sorted(packets, key=lambda x: x.time)
        flow["packets"] = packets

        proto = flow["protocol"]

        if proto not in PROTOCOL_RULES:
            continue

        rules = PROTOCOL_RULES[proto].get("cleaning_rules", {})

        # -------------------------
        # Duration check
        # -------------------------
        times = [pkt.time for pkt in packets]
        duration = times[-1] - times[0]

        if duration > rules.get("max_flow_duration", 999):
            continue

        # -------------------------
        # IAT check
        # -------------------------
        iats = np.diff(times)

        if len(iats) > 0:
            if max(iats) > rules.get("max_iat", 999):
                continue

        # -------------------------
        # Min packet
        # -------------------------
        if len(packets) < rules.get("min_packets", 1):
            continue

        # -------------------------
        # Protocol-specific validation
        # -------------------------
        if not validate_protocol_flow(flow, rules):
            continue

        cleaned.append(flow)

    return cleaned

def decode_flow_key(flow_key):

    protocol = flow_key[0]
    values = flow_key[1:]

    fields = PROTOCOL_RULES[protocol]["flow_key"]

    return protocol, dict(zip(fields, values))

def extract_basic_sequences_features(pkt, prev_time, key_dict):
    feature_map = {}

    # -----------------------------
    # IAT
    # -----------------------------
    timestamp = float(pkt.time)

    if prev_time is None:
        feature_map["iat"] = 0
    else:
        feature_map["iat"] = timestamp - prev_time

    # -----------------------------
    # packet length
    # -----------------------------
    feature_map["packet_length"] = len(pkt)
    return feature_map, timestamp    
def extract_direction (protocol,pkt,key_dict):
    
    feature_map = {}
    # direction
    if protocol == "dhcp" and UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

        if sport == 68 and dport == 67:
            direction = 0
        elif sport == 67 and dport == 68:
            direction = 1
    # ARP 
    elif protocol == "arp" and pkt.haslayer(ARP):
        src = pkt[ARP].psrc
        direction = 0 if src == key_dict["src_ip"] else 1

    elif "src_ip" in key_dict:
        if IP in pkt:
            src = pkt[IP].src
        elif IPv6 in pkt:
            src = pkt[IPv6].src
        else:
            direction = 0

        direction = 0 if src == key_dict["src_ip"] else 1
    feature_map["direction"] = direction
    return feature_map

def extract_flag(pkt):
    feature_map={}
    # TCP
    if TCP in pkt:
        feature_map["tcp_flags"] = int(pkt[TCP].flags)

    # DNS
    if pkt.haslayer("DNS"):
        dns_layer = pkt["DNS"]
        feature_map["dns_type"] = 0 if dns_layer.qr == 0 else 1

    # ICMP
    if ICMP in pkt:
        feature_map["icmp_type"] = pkt[ICMP].type

    # DHCP
    if pkt.haslayer("DHCP"):
        for opt in pkt["DHCP"].options:
            if isinstance(opt, tuple) and opt[0] == "message-type":
                feature_map["dhcp_msg_type"] = opt[1]

    # ARP
    if pkt.haslayer("ARP"):
        feature_map["arp_opcode"] = pkt["ARP"].op
    
    return feature_map


def filter_valid_ack( packets):

    filtered = []

    last_data_direction = None
    last_was_ack = False

    for pkt in packets:

        if not pkt.haslayer(TCP):
            continue

        flags = int(pkt[TCP].flags)

        # -----------------------
        # DATA (PSH)
        # -----------------------
        if flags & 0x08:  # PSH
            filtered.append(pkt)
            last_data_direction = pkt[IP].src
            last_was_ack = False

        # -----------------------
        # ACK
        # -----------------------
        elif flags == 16:

            #  nếu chưa có DATA trước → bỏ
            if last_data_direction is None:
                continue

            #  ACK liên tiếp → bỏ
            if last_was_ack:
                continue

            #  ACK cùng chiều DATA → bỏ
            if pkt[IP].src == last_data_direction:
                continue

            # ✅ hợp lệ
            filtered.append(pkt)
            last_was_ack = True

        else:
            # các loại khác giữ nguyên
            filtered.append(pkt)
            last_was_ack = False

    return filtered


def get_pkt_by_tcp_stage(protocol, flow):

    packets = sorted(flow["packets"], key=lambda x: x.time)
    stages = PROTOCOL_RULES[protocol].get("stages", [])
    stage_pkts = {}

    if protocol not in ["http", "https"]:
        return {}

    # -----------------------------
    # 1. HANDSHAKE
    # -----------------------------
    if "handshake" in stages:
        handshake = []

        for i in range(len(packets)):
            pkt = packets[i]

            if pkt.haslayer(TCP):
                flags = int(pkt[TCP].flags)

                # SYN (no ACK)
                if (flags & 0x02) and not (flags & 0x10):
                    handshake = packets[i:i+3]
                    break

        if len(handshake) == 3:
            stage_pkts["handshake"] = handshake
        else: stage_pkts["handshake"] = []  

    # -----------------------------
    # 2. CLOSING
    # -----------------------------
    if "closing" in stages:
        closing = []

        for i in range(len(packets)):
            pkt = packets[i]

            if pkt.haslayer(TCP):
                flags = int(pkt[TCP].flags)

                if flags & 0x01:  # FIN
                    closing = packets[i:i+4]
                    break

        if len(closing) >= 1:
            stage_pkts["closing"] = closing
        else: stage_pkts["closing"] = []

    # -----------------------------
    # 3. DATA
    # -----------------------------
    if "data" in stages:
        data = []

        # lấy phần giữa handshake và closing
        start = 0
        end = len(packets)

        # handshake
        if stage_pkts.get("handshake"):
            start = packets.index(stage_pkts["handshake"][-1]) + 1

        # closing
        if stage_pkts.get("closing"):
            end = packets.index(stage_pkts["closing"][0])
        if start < end:
            data = packets[start:end]

        # data = filter_valid_ack(data)

        if len(data) > 0:
            stage_pkts["data"] = data
        else: stage_pkts["data"] = []

    return stage_pkts
def extract_dataset_file(protocol,fields,data,stages=None,output_csv=None):
    if stages:
        for s in stages:
                
            with open(f"dataset/{protocol}_{s}_sequences_dataset.csv", "w", newline="") as f:

                writer = csv.writer(f)

                # header
                header = ["flow_id"]

                
                header += list(fields,)

                writer.writerow(header)
                
                writer.writerows(data[s])

            print(f"{protocol} {s} dataset extracted")
    else:
        with open(output_csv, "w", newline="") as f:

            writer = csv.writer(f)

            # header
            header = ["flow_id"]

            
            header += list(fields,)

            writer.writerow(header)
            
            writer.writerows(data)

        print("Dataset extracted")