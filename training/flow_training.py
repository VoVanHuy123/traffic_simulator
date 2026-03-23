
import pandas as pd
from copulas.multivariate import GaussianMultivariate
protocol = "http"
import pickle
df = pd.read_csv(f"dataset/{protocol}_flow_dataset.csv")

features = [
    "flow_duration",
    "packet_count",
    "avg_packet_size",
]

model = GaussianMultivariate()

model.fit(df[features])
with open(f"models/flow_models/{protocol}_flow.pkl", "wb") as f:
    pickle.dump(model, f)


print("Model saved")