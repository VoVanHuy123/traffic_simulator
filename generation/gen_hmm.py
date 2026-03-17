import pickle
import numpy as np

# Load
model = pickle.load(open("models/hmm_model.pkl", "rb"))
scaler = pickle.load(open("models/scaler.pkl", "rb"))
dir_enc = pickle.load(open("models/dir_encoder.pkl", "rb"))
flag_enc = pickle.load(open("models/flag_encoder.pkl", "rb"))

# -----------------------------
# Generate sequence
# -----------------------------
n_packets = 15

X, states = model.sample(n_packets)

# inverse scale
X = scaler.inverse_transform(X)

print("Generated packets:\n")

for row in X:

    iat = max(row[0], 0)
    packet_length = int(max(row[1], 40))

    direction = int(round(row[2]))
    tcp_flag = int(round(row[3]))

    direction = dir_enc.inverse_transform([direction])[0]
    tcp_flag = flag_enc.inverse_transform([tcp_flag])[0]

    print(iat, packet_length, direction, tcp_flag)