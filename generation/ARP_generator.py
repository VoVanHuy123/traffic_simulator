import numpy as np
import pandas as pd
import joblib
from base_generator import BaseFlowGenerator

class ARPFlowGenerator(BaseFlowGenerator):

    def generate_flow(self, n_packets=2):
        timing = self.generate_timing(n_packets)

        packets = [
            {"direction": 0, "packet_length": 60, "tcp_flags": 0, "iat": timing[0]},
            {"direction": 1, "packet_length": 60, "tcp_flags": 0, "iat": timing[1]}
        ]

        return pd.DataFrame(packets)