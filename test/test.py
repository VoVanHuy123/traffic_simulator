import pandas as pd
import matplotlib.pyplot as plt

# dataset thật
real_df = pd.read_csv("dataset/http1_flow_dataset.csv")

# dataset generate từ model
syn_df = pd.read_csv("synthetic/http_synthetic_flows.csv")
plt.hist(real_df["packet_count"], bins=30, alpha=0.5, label="real")
plt.hist(syn_df["packet_count"], bins=60, alpha=1, label="synthetic")

plt.title("Packet Count Distribution")
plt.xlabel("packet_count")
plt.ylabel("frequency")

plt.legend()
plt.show()