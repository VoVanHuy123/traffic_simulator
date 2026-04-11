
import pandas as pd
from copulas.multivariate import GaussianMultivariate, VineCopula
import numpy as np
protocol = "dhcp"
import pickle

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
            "avg_packet_size",
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

    def model_train(self):
        df = pd.read_csv(self.dataset_path)

        # ===== PREPROCESS =====
        df = df[self.features].copy()

        df["flow_duration"] = np.log1p(df["flow_duration"])
        df["packet_count"] = np.log1p(df["packet_count"])
        df["avg_packet_size"] = np.log1p(df["avg_packet_size"])
        df["total_bytes"] = np.log1p(df["total_bytes"])
        self.model.fit(df[self.features])
        with open(self.model_path, "wb") as f:
            pickle.dump(self.model, f)
        print(f"Model flow_{self.protocol} saved in {self.model_path}")

    def train2(self):

        df = pd.read_csv(self.dataset_path)
        df = df[self.features].copy()

        # ⭐ Transform ONLY heavy-tail features
        df["flow_duration"] = np.log1p(df["flow_duration"])
        df["total_bytes"] = np.log1p(df["total_bytes"])

        self.model.fit(df)

        with open(self.model_path, "wb") as f:
            pickle.dump(self.model, f)

        print("✅ Model trained & saved")


