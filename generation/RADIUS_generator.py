import random
import numpy as np
from scapy.all import IP, UDP, Raw
from scapy.layers.radius import Radius
from .base_generator import BaseFlowGenerator


class RADIUSFlowGenerator(BaseFlowGenerator):
    protocol = "radius"

    def build_packets(self, all_df, base_time):
        packets = []
        time = base_time

        for df in all_df:
            client_ip = f"192.168.1.{np.random.randint(1, 100)}"
            server_ip = f"192.168.1.{np.random.randint(1, 100)}"
            radius_id = random.randint(0, 255)
            authenticator = bytes(random.getrandbits(8) for _ in range(16))

            for row in df.to_dict("records"):
                time += float(row["iat"])

                direction = int(row["direction"])
                code = int(row["radius_code"])
                pkt_len = int(row["packet_length"])

                if direction == 0:
                    sip, dip = client_ip, server_ip
                    sport, dport = random.randint(1024, 65535), 1812
                else:
                    sip, dip = server_ip, client_ip
                    sport, dport = 1812, random.randint(1024, 65535)

                pkt = IP(src=sip, dst=dip) / UDP(sport=sport, dport=dport) / Radius(
                    code=code, id=radius_id, authenticator=authenticator
                )

                current_len = len(pkt)
                if current_len < pkt_len:
                    pkt = pkt / Raw(load=b"\x00" * (pkt_len - current_len))

                pkt.time = time
                packets.append(pkt)

        return packets
