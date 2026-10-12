import numpy as np
from scapy.all import IP, UDP
from scapy.contrib.gtp import GTPHeader
from .base_generator import BaseFlowGenerator


class GTPFlowGenerator(BaseFlowGenerator):
    protocol = "gtp"

    def build_packets(self, all_df, base_time):
        packets = []
        time = base_time

        for df in all_df:
            sgsn_ip = f"10.0.0.{np.random.randint(1, 100)}"
            ggsn_ip = f"10.0.0.{np.random.randint(101, 200)}"

            for row in df.to_dict("records"):
                time += float(row["iat"])

                direction = int(row["direction"])
                gtp_type = int(row["gtp_type"])

                if direction == 0:
                    sip, dip = sgsn_ip, ggsn_ip
                else:
                    sip, dip = ggsn_ip, sgsn_ip

                pkt = IP(src=sip, dst=dip) / UDP(sport=2123, dport=2123) / GTPHeader(
                    version=1, PT=1, gtp_type=gtp_type, teid=0
                )
                pkt.time = time
                packets.append(pkt)

        return packets
