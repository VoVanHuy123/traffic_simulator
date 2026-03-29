import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import numpy as np
import pandas as pd
import joblib
import numpy as np
import random
from scapy.all import Ether, ARP, wrpcap
from .base_generator import BaseFlowGenerator

class ARPFlowGenerator(BaseFlowGenerator):
    protocol = "arp"

    

    def decode_packet(self, parts):

        direction = int(parts[0])
        flag = int(parts[1])

        # packet_length bin → value
        length_bin = int(parts[2])
        length_map = {
            0: np.random.randint(40, 70),
            1: np.random.randint(70, 90),
            2: np.random.randint(90, 100),
            3: np.random.randint(100, 128)
        }

        # iat bin → value
        iat_bin = int(parts[3])
        iat_map = {
            0: np.random.uniform(0.000001, 0.0001),
            1: np.random.uniform(0.0001, 0.01),
            2: np.random.uniform(0.01, 0.1),
            3: np.random.uniform(0.1, 1)
        }

        return {
            "direction": direction,
            "arp_opcode": flag,
            "packet_length": length_map[length_bin],
            "iat": iat_map[iat_bin]
        }
    from scapy.all import Ether, ARP, wrpcap



    def random_mac(self):
        return "02:%02x:%02x:%02x:%02x:%02x" % tuple(
            random.randint(0, 255) for _ in range(5)
        )


    def to_pcap(self,all_df, filename="arp_output.pcap"):
        packets = []
        time = 0
        base_time = random.uniform(1700000000, 2000000000)
        time = base_time
        for df in all_df:
            time += random.uniform(0.01, 0.5)
            # random IP
            src_ip = f"192.168.1.{np.random.randint(1, 100)}"
            dst_ip = f"192.168.1.{np.random.randint(1, 100)}"

            src_mac = self.random_mac()
            dst_mac = self.random_mac()

            for row in df.to_dict("records"):

                time += float(row["iat"])

                direction = int(row["direction"])
                opcode = int(row["arp_opcode"])
                pkt_len = int(row["packet_length"])
                pkt_len = 60

                # -------- REQUEST --------
                if direction == 0:  # client

                    pkt = Ether(
                        src=src_mac,
                        dst="ff:ff:ff:ff:ff:ff"  # broadcast
                    ) / ARP(
                        op=opcode,
                        # op=1,
                        hwsrc=src_mac,
                        psrc=src_ip,
                        hwdst="00:00:00:00:00:00",
                        pdst=dst_ip
                    )

                # -------- RESPONSE --------
                else:  # server

                    pkt = Ether(
                        src=dst_mac,
                        dst=src_mac
                    ) / ARP(
                        op=opcode,
                        # op=2,
                        hwsrc=dst_mac,
                        psrc=dst_ip,
                        hwdst=src_mac,
                        pdst=src_ip
                    )

                # 👉 padding cho đủ length
                current_len = len(pkt)
                if current_len < pkt_len:
                    pkt = pkt / (b"\x00" * (pkt_len - current_len))

                pkt.time = time
                packets.append(pkt)

        wrpcap(filename, packets)
        print(f" Saved {filename}")