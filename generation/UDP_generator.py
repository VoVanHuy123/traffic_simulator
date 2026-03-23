import numpy as np
import pandas as pd
import joblib
from base_generator import BaseFlowGenerator
class UDPFlowGenerator(BaseFlowGenerator):

    def generate_packet(self, direction):
        return {
            "direction": direction,
            "packet_length": int(np.clip(np.random.normal(200, 100), 60, 1500)),
            "tcp_flags": 0
        }


class DNSFlowGenerator(UDPFlowGenerator):

    def generate_flow(self, n_packets=4):
        timing = self.generate_timing(n_packets)

        packets = []

        for i in range(n_packets):
            direction = 0 if i % 2 == 0 else 1

            pkt = self.generate_packet(direction)

            # DNS pattern
            if direction == 0:
                pkt["packet_length"] = int(np.random.normal(80, 20))
            else:
                pkt["packet_length"] = int(np.random.normal(200, 50))

            pkt["iat"] = timing[i]
            packets.append(pkt)

        return pd.DataFrame(packets)
    
    
class DHCPFlowGenerator(UDPFlowGenerator):

    def generate_flow(self, n_packets=4):
        timing = self.generate_timing(n_packets)

        directions = [0,1,0,1]  # discover, offer, request, ack

        packets = []

        for i in range(len(directions)):
            pkt = self.generate_packet(directions[i])
            pkt["packet_length"] = int(np.random.normal(300, 50))
            pkt["iat"] = timing[i]
            packets.append(pkt)

        return pd.DataFrame(packets)