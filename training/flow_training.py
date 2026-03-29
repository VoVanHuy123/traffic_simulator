
import pandas as pd
from copulas.multivariate import GaussianMultivariate
protocol = "dhcp"
import pickle

class FlowTrainer:
    def __init__(self,protocol,dataset_path=None,model_path = None):
        self.dataset_path = dataset_path
        self.protocol = protocol
        self.model_path = model_path
        self.model = GaussianMultivariate()
    
        self.features = [
            "flow_duration",
            "packet_count",
            "avg_packet_size",
        ]
    def set_protocol(self,protocol):
        self.protocol = protocol
        self.dataset_path = f"dataset/{protocol}_flow_dataset.csv"
        self.model_path = f"dataset/{protocol}_flow_dataset.csv"
    def set_dataset_path(self,path):
        self.dataset_path = path
    def set_model_path(self,path):
        self.model_path = path

    def model_train(self):
        df = pd.read_csv(self.dataset_path)
        self.model.fit(df[self.features])
        with open(self.model_path, "wb") as f:
            pickle.dump(self.model, f)
        print(f"Model flow_{self.protocol} saved in {self.model_path}")


# df = pd.read_csv(f"dataset/{protocol}_flow_dataset.csv")
# features = [
#     "flow_duration",
#     "packet_count",
#     "avg_packet_size",
# ]

# model = GaussianMultivariate()

# model.fit(df[features])
# with open(f"models/flow_models/{protocol}_flow.pkl", "wb") as f:
#     pickle.dump(model, f)
# print("Model saved")