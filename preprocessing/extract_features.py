
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


def extract_features(flows, output_csv):

    rows = []
    headers = None

    for flow in flows:

        packets = sorted(flow["packets"], key=lambda x: x.time)
        protocol = flow["protocol"]
        key_dict = flow["key_dict"]

        # protocol = key_dict["protocol"] if "protocol" in key_dict else None

        packet_count = len(packets)

        sizes = [len(pkt) for pkt in packets]
        total_bytes = sum(sizes)
        avg_packet_size = float(np.mean(sizes)) if sizes else 0

        times = [float(pkt.time) for pkt in packets]

        if len(times) > 1:
            flow_duration = times[-1] - times[0]
            iat = np.diff(times)
            iat_mean = float(np.mean(iat))
        else:
            flow_duration = 0
            iat_mean = 0


        
        flow_duration = np.log1p(flow_duration)
        packet_count = np.log1p(packet_count)
        avg_packet_size = np.log1p(avg_packet_size)
        iat_mean = np.log1p(iat_mean)
        total_bytes = np.log1p(total_bytes)

        feature_dict = {
            **key_dict,
            "packet_count": packet_count,
            "total_bytes": total_bytes,
            "avg_packet_size": avg_packet_size,
            "flow_duration": flow_duration,
            "iat_mean": iat_mean
        }

        csv_feature_fields = PROTOCOL_RULES[protocol]["csv_feature_fields"]

         # init header 
        if headers is None:
            headers = list(csv_feature_fields)

        row = [feature_dict.get(f, None) for f in csv_feature_fields]

        rows.append(row)

    # -------------------------
    # WRITE CSV
    # -------------------------
    with open(output_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)

    print("Feature extraction completed")



def extract_packet_sequences(flows, output_csv):

    rows = []
    flow_id = 0

    for flow in flows:

        packets = sorted(flow["packets"], key=lambda x: x.time)
        protocol = flow["protocol"]
        key_dict = flow["key_dict"]
        # print(key_dict)
        if protocol not in PROTOCOL_RULES:
            continue

        seq_fields = PROTOCOL_RULES[protocol]["csv_sequence_fields"]

        times = [float(pkt.time) for pkt in packets]
        if len(times) <= 1:
            continue

        last_time = times[0]

        for i, pkt in enumerate(packets):

            
            feature_map = {}
            basic_feat, last_time = extract_basic_sequences_features(pkt,last_time,key_dict,protocol)
            # merge basic features
            feature_map.update(basic_feat)

            # direction
            direction_feat = extract_direction(protocol,pkt,key_dict)
            feature_map.update(direction_feat)
            
            #flag
            flags_feat = extract_flag(pkt)
            feature_map.update(flags_feat)

            row = [flow_id]

            for field in seq_fields:
                field = field.strip()
                row.append(feature_map.get(field, 0))

            rows.append(row)

        flow_id += 1

    # -----------------------------
    # WRITE CSV
    # -----------------------------
    extract_dataset_file(protocol,seq_fields,rows)

from stage_extract import extract_stages_sequences

# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    protocol = "http"

    input_pcap = f"data/{protocol}_pcap.pcap"

    flows = build_flows(input_pcap)

    flows = clean_flows(flows)
   
    extract_stages_sequences(protocol,flows,f"dataset/{protocol}_handshake_flow_dataset.csv")
    # extract_features(
    #     flows,
    #     f"dataset/{protocol}_flow_dataset.csv"
    # )
    # extract_packet_sequences(
    #     flows,
    #     f"dataset/{protocol}_sequences_dataset.csv"
    # )
  
