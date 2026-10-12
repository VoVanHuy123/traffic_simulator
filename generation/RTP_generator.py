import random
import numpy as np
from scapy.all import IP, UDP, Raw
from scapy.layers.rtp import RTP
from .base_generator import BaseFlowGenerator


class RTPFlowGenerator(BaseFlowGenerator):
    protocol = "rtp"

    def build_packets(self, all_df, base_time):
        packets = []
        time = base_time

        for df in all_df:
            src_ip = f"192.168.1.{np.random.randint(1, 100)}"
            dst_ip = f"192.168.1.{np.random.randint(1, 100)}"
            sport = random.randint(10000, 20000)
            dport = random.randint(10000, 20000)
            ssrc = random.randint(1, 2**32 - 1)
            seq = random.randint(0, 65535)
            ts = random.randint(0, 2**32 - 1)

            for row in df.to_dict("records"):
                time += float(row["iat"])

                direction = int(row["direction"])
                payload_type = int(row["rtp_payload_type"])
                pkt_len = int(row["packet_length"])

                if direction == 0:
                    sip, dip = src_ip, dst_ip
                else:
                    sip, dip = dst_ip, src_ip

                rtp_layer = RTP(
                    version=2,
                    payload_type=payload_type,
                    sequence=seq & 0xFFFF,
                    timestamp=ts & 0xFFFFFFFF,
                    sourcesync=ssrc,
                )
                pkt = IP(src=sip, dst=dip) / UDP(sport=sport, dport=dport) / rtp_layer

                current_len = len(pkt)
                if current_len < pkt_len:
                    payload = bytes(random.getrandbits(8) for _ in range(pkt_len - current_len))
                    pkt = pkt / Raw(load=payload)

                pkt.time = time
                packets.append(pkt)

                seq += 1
                ts += 160  # 20ms @ 8kHz sampling (PCMU)

        return packets
