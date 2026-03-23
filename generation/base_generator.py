import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import numpy as np
import pandas as pd
import joblib
from rules.protocol_rules import PROTOCOL_RULES


class BaseFlowGenerator:
    def __init__(self, protocol, model_dir="models/sequences_models"):
        self.protocol = protocol
        self.model_dir = model_dir

        # load HMM nếu có
        try:
            self.hmm_cont = joblib.load(f"{model_dir}/{protocol}/{protocol}_hmm_cont.pkl")
            self.scaler = joblib.load(f"{model_dir}/{protocol}/{protocol}_scaler.pkl")
        except:
            self.hmm_cont = None
            self.scaler = None

    # -----------------------------
    # Timing generator (reuse)
    # -----------------------------
    def generate_timing(self, n_packets):
        if self.hmm_cont:
            Xc, _ = self.hmm_cont.sample(n_packets)
            Xc = self.scaler.inverse_transform(Xc)
            return [max(x[0], 1e-6) for x in Xc]
        else:
            return np.random.exponential(scale=0.001, size=n_packets)

    # -----------------------------
    # Interface
    # -----------------------------
    # def generate_flow(self, n_packets):
    #     raise NotImplementedError
    def generate(self, n_packets=10):

        rules = PROTOCOL_RULES.get(self.protocol)
        sequence_fields = rules.get("csv_sequence_fields")
        cont_fields = ["iat", "packet_length"]
        disc_fields = [f for f in sequence_fields if f not in cont_fields]

        # sample
        Xc, _ = self.hmm_cont.sample(n_packets)
        Xd, _ = self.hmm_disc.sample(n_packets)

        # inverse scale
        Xc = self.scaler.inverse_transform(Xc)

        # decode state
        states = [self.inv_state_map[int(s[0])] for s in Xd]

        rows = []

        for i in range(n_packets):
            state_parts = states[i].split("_")

            row = {
                "iat": max(Xc[i][0], 1e-6),
                "packet_length": int(np.clip(Xc[i][1],*rules.get("packet_size")))
            }

            # # dynamic fields (tùy protocol)
            # if len(state_parts) == 2:
            #     row["direction"] = int(state_parts[0])
            #     row["flag"] = int(state_parts[1])
            # -------- dynamic discrete --------
            for j, field in enumerate(disc_fields):
                row[field] = int(state_parts[j])

            rows.append(row)

        return pd.DataFrame(rows)