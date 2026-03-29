import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from abc import ABC, abstractmethod
import numpy as np
import pandas as pd
import joblib
from rules.protocol_rules import PROTOCOL_RULES


class BaseFlowGenerator:
    protocol= ""
    model_dir = "models/sequences_models"
    def __init__(self):
        self.inv_state_map = None
        self.hmm = None
        try:
            self.hmm = joblib.load(f"{self.model_dir}/{self.protocol}/{self.protocol}_hmm.pkl")
            self.inv_state_map = joblib.load(f"{self.model_dir}/{self.protocol}/{self.protocol}_inv_state_map.pkl")

            self.hmm_cont = joblib.load(f"{self.model_dir}/{self.protocol}/{self.protocol}_hmm_cont.pkl")
            self.scaler = joblib.load(f"{self.model_dir}/{self.protocol}/{self.protocol}_scaler.pkl")
        except:
            self.hmm_cont = None
            self.scaler = None

    def match(self, protocol):
        return self.protocol == protocol


    def set_model(self, stage=None):
        if stage:
            base = f"{self.model_dir}/{self.protocol}/{stage}/{self.protocol}_{stage}"
        else:
            base = f"{self.model_dir}/{self.protocol}/{self.protocol}"

        self.hmm = joblib.load(f"{base}_hmm.pkl")
        self.inv_state_map = joblib.load(f"{base}_inv_state_map.pkl")

    def build_bins(self,value_range, bin_edges):
        """
        (min,max) + [edges]
        -> list[(low,high)]
        """
        low, high = value_range
        edges = [low] + list(bin_edges) + [high]

        return [(edges[i], edges[i+1]) for i in range(len(edges)-1)]
    # DECODE BIN → VALUE
    
    def decode_packet(self, parts):

        cfg = PROTOCOL_RULES[self.protocol]
        seq_fields = cfg["csv_sequence_fields"]

        direction = int(parts[0])
        proto_state = int(parts[1])
        length_bin = int(parts[2])
        iat_bin = int(parts[3])

        # build bins
        length_bins = self.build_bins(
            cfg["packet_size"],
            cfg["packet_length_bin"]
        )

        iat_bins = self.build_bins(
            cfg["flow_duration"],
            cfg["iat_bin"]
        )

        packet_length = np.random.randint(*length_bins[length_bin])
        iat = np.random.uniform(*iat_bins[iat_bin])

        # dynamic packet
        packet = {}

        for field in seq_fields:

            if field == "direction":
                packet[field] = direction

            elif field == "packet_length":
                packet[field] = packet_length

            elif field == "iat":
                packet[field] = iat

            else:
                # dhcp_msg_type / arp_opcode / tcp_flags...
                packet[field] = proto_state

        return packet

    
    # GENERATE
    def generate(self, n_packets=10):
        Xd, _ = self.hmm.sample(n_packets)

        states = [self.inv_state_map[int(s[0])] for s in Xd]

        rows = []

        for s in states:
            parts = s.split("_")
            row = self.decode_packet(parts)
            rows.append(row)

        return pd.DataFrame(rows)
    def generate_sequences(self,n_packets):
        return self.generate(n_packets)
    
    def to_pcap(self):
        raise NotImplementedError
    
