import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

############################################
# CONFIG
############################################

REAL_PATH = "dataset/real_sequences.csv"
SIM_PATH = "dataset/sim_sequences.csv"

############################################
# DHCP STAGE MAP
############################################

DHCP_STAGE_MAP = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    5: "ACK"
}

############################################
# LOAD DATA
############################################

real_df = pd.read_csv(REAL_PATH)
sim_df = pd.read_csv(SIM_PATH)

# convert msg type -> stage name
real_df["stage"] = real_df["dhcp_msg_type"].map(DHCP_STAGE_MAP)
sim_df["stage"] = sim_df["dhcp_msg_type"].map(DHCP_STAGE_MAP)

print("Loaded dataset ✔")

############################################
# 1️⃣ STAGE DISTRIBUTION
############################################

def compare_stage_distribution(real_df, sim_df):

    real_dist = real_df["stage"].value_counts(normalize=True)
    sim_dist = sim_df["stage"].value_counts(normalize=True)

    stages = ["DISCOVER","OFFER","REQUEST","ACK"]

    real_vals = [real_dist.get(s,0) for s in stages]
    sim_vals = [sim_dist.get(s,0) for s in stages]

    x = np.arange(len(stages))

    plt.figure(figsize=(7,4))
    plt.bar(x-0.2, real_vals, width=0.4, label="REAL")
    plt.bar(x+0.2, sim_vals, width=0.4, label="SIM")

    plt.xticks(x, stages)
    plt.ylabel("Ratio")
    plt.title("DHCP Stage Distribution Comparison")
    plt.legend()
    plt.tight_layout()
    plt.show()

############################################
# 2️⃣ TRANSITION MATRIX
############################################

def transition_matrix(df):

    stages = ["DISCOVER","OFFER","REQUEST","ACK"]
    idx = {s:i for i,s in enumerate(stages)}

    mat = np.zeros((4,4))

    for _, flow in df.groupby("flow_id"):

        seq = list(flow["stage"])

        for i in range(len(seq)-1):
            a = idx[seq[i]]
            b = idx[seq[i+1]]
            mat[a,b] += 1

    mat += 1e-9
    mat = mat / mat.sum(axis=1, keepdims=True)

    return mat


def compare_stage_transition(real_df, sim_df):

    real_mat = transition_matrix(real_df)
    sim_mat = transition_matrix(sim_df)

    diff = np.linalg.norm(real_mat - sim_mat)

    print("\nStage Transition Difference:", diff)

    if diff < 0.2:
        print("✅ DHCP behavior preserved")
    else:
        print("❌ DHCP dynamics mismatch")

############################################
# 3️⃣ STAGE DURATION
############################################

def stage_duration(df):

    durations = (
        df.groupby(["flow_id","stage"])
        .size()
        .reset_index(name="duration")
    )

    return durations.groupby("stage")["duration"].mean()


def compare_stage_duration(real_df, sim_df):

    real_dur = stage_duration(real_df)
    sim_dur = stage_duration(sim_df)

    compare = real_dur.to_frame("REAL")
    compare["SIM"] = sim_dur

    print("\nAverage Stage Duration")
    print(compare)

############################################
# 4️⃣ ORDER ACCURACY ⭐⭐⭐⭐⭐
############################################

VALID_DHCP_SEQUENCE = [
    ["DISCOVER","OFFER","REQUEST","ACK"]
]

def stage_order_accuracy(df):

    valid = 0
    total = 0

    for _, flow in df.groupby("flow_id"):

        seq = list(flow["stage"])

        if seq == VALID_DHCP_SEQUENCE[0]:
            valid += 1

        total += 1

    acc = valid / total if total else 0
    return acc

############################################
# RUN
############################################

if __name__ == "__main__":

    print("\n========== FLOW STAGE SIMILARITY ==========")

    compare_stage_distribution(real_df, sim_df)

    compare_stage_transition(real_df, sim_df)

    compare_stage_duration(real_df, sim_df)

    real_acc = stage_order_accuracy(real_df)
    sim_acc = stage_order_accuracy(sim_df)

    print("\nStage Order Accuracy")
    print("REAL :", real_acc)
    print("SIM  :", sim_acc)