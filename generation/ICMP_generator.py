import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import numpy as np
import pandas as pd
import joblib
import random
from scapy.all import wrpcap, ICMP, IP, Raw
from .base_generator import BaseFlowGenerator

class ICMPFlowGenerator(BaseFlowGenerator):
    protocol = "icmp"

    

    def to_pcap(self,all_df, filename="icmp_output.pcap"):

        packets = []

        # base time (realistic)
        base_time = random.uniform(1700000000, 1800000000)
        time = base_time

        for df in all_df:

            # mỗi flow là 1 cặp IP
            src_ip = f"192.168.1.{np.random.randint(1, 100)}"
            dst_ip = f"192.168.1.{np.random.randint(1, 100)}"

            icmp_id = np.random.randint(0, 65535)
            seq = 0

            # gap giữa flows
            time += random.uniform(0.01, 0.2)

            for row in df.to_dict("records"):

                time += float(row["iat"])

                direction = int(row["direction"])
                icmp_type = int(row["icmp_type"])
                pkt_len = int(row["packet_length"])

                # -------- REQUEST --------
                if direction == 0:
                    sip, dip = src_ip, dst_ip
                else:
                    sip, dip = dst_ip, src_ip

                pkt = IP(src=sip, dst=dip) / ICMP(
                    type=icmp_type,
                    id=icmp_id,
                    seq=seq
                )

                # -------- PAYLOAD --------
                current_len = len(pkt)

                if current_len < pkt_len:
                    payload_size = pkt_len - current_len

                    # random payload 
                    payload = bytes(random.getrandbits(8) for _ in range(payload_size))

                    pkt = pkt / Raw(load=payload)

                pkt.time = time
                packets.append(pkt)

                seq += 1

        wrpcap(filename, packets)
        print(f"Saved {filename}")