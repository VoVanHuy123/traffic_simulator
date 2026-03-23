import numpy as np
import pandas as pd
import joblib
from base_generator import BaseFlowGenerator

class ICMPFlowGenerator(BaseFlowGenerator):

    def generate_flow(self, n_packets=6):
        timing = self.generate_timing(n_packets)

        packets = []

        for i in range(n_packets):
            direction = i % 2

            packets.append({
                "direction": direction,
                "packet_length": int(np.random.normal(100, 20)),
                "tcp_flags": 0,
                "iat": timing[i]
            })

        return pd.DataFrame(packets)