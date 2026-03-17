import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from hmmlearn.hmm import GaussianHMM
import pickle

# -----------------------------
# Load dataset
# -----------------------------
df = pd.read_csv("data/http_flow_dataset.csv")

# -----------------------------
# Encode categorical
# -----------------------------
dir_enc = LabelEncoder()
flag_enc = LabelEncoder()

df["direction"] = dir_enc.fit_transform(df["direction"])
df["tcp_flags"] = flag_enc.fit_transform(df["tcp_flags"])

# -----------------------------
# Feature selection
# -----------------------------
features = ["iat", "packet_length", "direction", "tcp_flags"]

X = df[features].values

# -----------------------------
# Scale features
# -----------------------------
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# -----------------------------
# Build sequence lengths
# -----------------------------
lengths = []

for fid, group in df.groupby("flow_id"):
    lengths.append(len(group))

# -----------------------------
# Train HMM
# -----------------------------
model = GaussianHMM(
    n_components=6,
    covariance_type="diag",
    n_iter=200
)

model.fit(X_scaled, lengths)

print("HMM trained")

# -----------------------------
# Save model
# -----------------------------
pickle.dump(model, open(f"models/sequences_models/hmm_model.pkl", "wb"))
pickle.dump(scaler, open(f"models/sequences_models/scaler.pkl", "wb"))
pickle.dump(dir_enc, open(f"models/sequences_models/dir_encoder.pkl", "wb"))
pickle.dump(flag_enc, open(f"models/sequences_models/flag_encoder.pkl", "wb"))

print("Model saved")