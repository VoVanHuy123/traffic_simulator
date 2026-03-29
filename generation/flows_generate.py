
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import pickle
import pandas as pd
import os
import numpy as np
from rules.protocol_rules import PROTOCOL_RULES

def generate_flow(protocol,sample):


    model = pickle.load(open(f"models/flow_models/{protocol}_flow.pkl","rb"))
    X_sample = model.sample(sample)


    rules = PROTOCOL_RULES[protocol]

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


