
import pandas as pd
from copulas.multivariate import GaussianMultivariate, VineCopula
import numpy as np
import pickle
from rules.protocol_rules import PROTOCOL_RULES

class FlowTrainer:
    def __init__(self,protocol,dataset_path=None,model_path = None):
        self.dataset_path = dataset_path
        self.protocol = protocol
        self.model_path = model_path
        # self.model = GaussianMultivariate()
        self.model = VineCopula("center")
    
        self.features = [
            "flow_duration",
            "packet_count",
            "total_bytes",
        ]
    def set_protocol(self,protocol):
        self.protocol = protocol
        self.dataset_path = f"dataset/{protocol}/{protocol}_flow_dataset.csv"
        self.model_path = f"models/flow_models/{protocol}_flow.pkl"
    def set_dataset_path(self,path):
        self.dataset_path = path
    def set_model_path(self,path):
        self.model_path = path

    def _load_flow_data(self):
        df = pd.read_csv(self.dataset_path)

        df = df[self.features].copy()
        rules = PROTOCOL_RULES[self.protocol]

        df["avg_packet_size"] = df["total_bytes"] / df["packet_count"].replace(0, 1)
        total_min = df["packet_count"] * rules["packet_size"][0]
        total_max = df["packet_count"] * rules["packet_size"][1]

        df = df[
            df["packet_count"].between(*rules["packet_count"]) &
            df["flow_duration"].between(*rules["flow_duration"]) &
            df["avg_packet_size"].between(*rules["packet_size"]) &
            df["total_bytes"].ge(total_min) &
            df["total_bytes"].le(total_max)
        ].copy()

        # Remove extreme outliers in heavy-tailed features.
        for col in ["flow_duration", "total_bytes"]:
            lower = df[col].quantile(0.001)
            upper = df[col].quantile(0.999)
            df = df[df[col].between(lower, upper)]

        return df[self.features].copy()

    def model_train(self):
        df = self._load_flow_data()

        df["flow_duration"] = np.log1p(df["flow_duration"])
        df["packet_count"] = np.log1p(df["packet_count"])
        df["total_bytes"] = np.log1p(df["total_bytes"])

        self.model.fit(df)
        with open(self.model_path, "wb") as f:
            pickle.dump(self.model, f)
        print(f"Model flow_{self.protocol} saved in {self.model_path}")

    def train2(self):
        df = self._load_flow_data()

        df["flow_duration"] = np.log1p(df["flow_duration"])
        df["packet_count"] = np.log1p(df["packet_count"])
        df["total_bytes"] = np.log1p(df["total_bytes"])

        self.model.fit(df)

        with open(self.model_path, "wb") as f:
            pickle.dump(self.model, f)

        print("✅ Model trained & saved")


