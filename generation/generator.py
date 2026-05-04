import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import hashlib
import pickle
import pandas as pd
import os
import numpy as np
from rules.protocol_rules import PROTOCOL_RULES

class Generator:
    protocol = ""
    registry = None
    flows_model = None
    sequences_model = None
    sequences_model = None

    def __init__(self,protocol,registry):
        self.registry = registry
        self.protocol = protocol
        self.flows_model = pickle.load(open(f"models/flow_models/{self.protocol}_flow.pkl","rb"))
        self.generator = self.registry.get_generator_handler(self.protocol)
    # def __init__(self,registry):
    #     self.registry = registry
    #     self.flows_model = pickle.load(open(f"models/flow_models/{self.protocol}_flow.pkl","rb"))
    #     self.generator = self.registry.get_generator_handler(self.protocol)
    #     print("NEED SET PROTOCOL")

    def set_protocoL(self,protocol):
        self.protocol = protocol
        self.flows_model = pickle.load(open(f"models/flow_models/{protocol}_flow.pkl","rb"))
        self.generator = self.registry.get_generator_handler(protocol)

    def _get_flow_seed(self, num_flows):
        key = f"{self.protocol}:{num_flows}"
        return int(hashlib.md5(key.encode("utf-8")).hexdigest()[:8], 16)

    def generate_flows_features(self, num_flows):
        seed = self._get_flow_seed(num_flows)
        np.random.seed(seed)

        model = pickle.load(open(f"models/flow_models/{self.protocol}_flow.pkl","rb"))
        X_sample = model.sample(num_flows)

        rules = PROTOCOL_RULES[self.protocol]

        df = pd.DataFrame(X_sample, columns=[
            "flow_duration",
            "packet_count",
            "total_bytes",
        ])

        df["flow_duration"] = np.expm1(df["flow_duration"]).abs()
        df["packet_count"] = np.expm1(df["packet_count"]).abs().astype(int).clip(*rules["packet_count"])
        df.loc[df["packet_count"] < 1, "packet_count"] = 1

        df["total_bytes"] = np.expm1(df["total_bytes"]).abs().round().astype(int)
        min_total = df["packet_count"] * rules["packet_size"][0]
        max_total = df["packet_count"] * rules["packet_size"][1]
        df["total_bytes"] = df["total_bytes"].clip(min_total, max_total)

        df["avg_packet_size"] = (df["total_bytes"] / df["packet_count"].replace(0, 1)).clip(*rules["packet_size"])
        df["total_bytes"] = (df["avg_packet_size"] * df["packet_count"]).round().astype(int)

        df["packet_rate"] = df["packet_count"] / df["flow_duration"].replace(0, 1e-6)
        df["iat_mean"] = df["flow_duration"] / df["packet_count"].replace(0, 1)

        return df
    
    def generate_sequences_features(self,packet_count):
        if hasattr(self.generator, "generate_sequences_by_stages"):
            result = self.generator.generate_sequences_by_stages(int(packet_count))
            if isinstance(result, tuple):
                df, _ = result
            else:
                df = result
        else:
            df = self.generator.generate_sequences(int(packet_count))
        return df
    
    def export_pcap(self,all_flows,output_path):
        self.generator.to_pcap(all_flows,output_path)




