import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from scapy.all import rdpcap, ARP, ICMP, IP, IPv6, TCP, UDP, BOOTP
import csv
import numpy as np
from collections import defaultdict
from scapy.all import *
from rules.protocol_rules import PROTOCOL_RULES
from data_clean import *
def extract_stages_sequences(protocol,flows, output_csv):
    
    if protocol in ["tcp","http","https"]:
        extract_tcp_stage_sequences(protocol,flows, output_csv)

def extract_tcp_stage_sequences(protocol,flows, output_csv):
    rows ={}

    stages = PROTOCOL_RULES[protocol].get("stages")
    for s in stages:
        rows[s] = []
    flow_id = 0

    for flow in flows:

        protocol = flow["protocol"]
        key_dict  = flow["key_dict"]
        if protocol not in ["tcp","http", "https"]:
            continue

        packets = sorted(flow["packets"], key=lambda x: x.time)

        if len(packets) < 3:
            continue

        if protocol not in PROTOCOL_RULES:
            continue

        seq_fields = PROTOCOL_RULES[protocol]["csv_sequence_fields"]

    
        stage_pkts = get_pkt_by_tcp_stage(protocol,flow)
        has_any_stage = False  

        for s in stages:
            pkts = stage_pkts.get(s, [])

            if not pkts:
                continue

            has_any_stage = True

            last_time = float(pkts[0].time)

            for j, pkt in enumerate(pkts):

                feature_map = {}
                basic_feat, last_time = extract_basic_sequences_features(pkt,last_time,key_dict)
                # merge basic features
                feature_map.update(basic_feat)

                # direction
                direction_feat = extract_direction(protocol,pkt,key_dict)
                feature_map.update(direction_feat)

                # tcp flags
                feature_map["tcp_flags"] = int(pkt[TCP].flags)


                row = [flow_id]

                for field in seq_fields:
                    field = field.strip()
                    row.append(feature_map.get(field, 0))

                rows[s].append(row)

        if has_any_stage:
            flow_id += 1

    extract_dataset_file(protocol,seq_fields,rows,stages,None)