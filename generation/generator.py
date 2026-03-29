import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
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

    def generate_flows_features(self,num_flows):

        model = pickle.load(open(f"models/flow_models/{self.protocol}_flow.pkl","rb"))
        X_sample = model.sample(num_flows)


        rules = PROTOCOL_RULES[self.protocol]

        df = pd.DataFrame(X_sample, columns=[
            "flow_duration",
            "packet_count",
            "avg_packet_size",
        ])
        df["flow_duration"] = np.expm1(df["flow_duration"]).abs()

        df["packet_count"] = np.expm1(df["packet_count"]).abs().astype(int).clip(*rules["packet_count"])
        # df["packet_count"] = np.expm1(np.clip(df["packet_count"], 0, 10)).astype(int).clip(*rules["packet_count"])

        df["avg_packet_size"] = np.expm1(df["avg_packet_size"]).clip(*rules["packet_size"])

        df["packet_rate"] = df["packet_count"] / df["flow_duration"]

        df["iat_mean"] = df["flow_duration"] / df["packet_count"]

        return df
    
    def generate_sequences_features(self,packet_count):
        df = self.generator.generate_sequences(int(packet_count))
        return df
    
    def export_pcap(self,all_lows,output_path):
        self.generator.to_pcap(all_lows,output_path)




