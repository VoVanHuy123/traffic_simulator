import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import pandas as pd
import numpy as np
from scipy.spatial.distance import jensenshannon
import matplotlib.pyplot as plt
import seaborn as sns
from rules.protocol_rules import PROTOCOL_RULES
from scipy.stats import ks_2samp


class Evaluator:

    def __init__(self, protocol):
        self.protocol = protocol
        self.rules = PROTOCOL_RULES[protocol]
        self.stages = PROTOCOL_RULES[protocol].get("stages")

    def set_dataset_path(self, path):
        self.dataset_path = path

    def flow_evaluation(self, real_flows_path, sim_flows_path):
        real_df = pd.read_csv(real_flows_path)
        sim_df = pd.read_csv(sim_flows_path)

        features = self.rules.get("evaluation_features")

        for feature in features:

            plt.figure(figsize=(8,5))

            sns.histplot(
                real_df[feature],
                color="blue",
                label="REAL",
                stat="density",
                bins=50,
                kde=True,
                alpha=0.5
            )

            sns.histplot(
                sim_df[feature],
                color="red",
                label="SIMULATED",
                stat="density",
                bins=50,
                kde=True,
                alpha=0.5
            )

            plt.title(f"Distribution Comparison: {feature}")
            plt.xlabel(feature)
            plt.ylabel("Density")
            plt.legend()

            plt.tight_layout()
            plt.savefig(f"evaluator/output/{self.protocol}/compare_{feature}.png")
            plt.show()
    def plot_iat_autocorrelation(self, real_flows_path, sim_flows_path):
        real_df = pd.read_csv(real_flows_path)
        sim_df = pd.read_csv(sim_flows_path)
        real_iat = real_df["iat"]
        sim_iat = sim_df["iat"]

        lags = 50

        real_auto = [real_iat.autocorr(lag=i) for i in range(lags)]
        sim_auto = [sim_iat.autocorr(lag=i) for i in range(lags)]

        plt.figure(figsize=(8,5))
        plt.plot(real_auto, label="REAL")
        plt.plot(sim_auto, label="SIMULATED")

        plt.title("IAT Autocorrelation")
        plt.xlabel("Lag")
        plt.ylabel("Autocorrelation")
        plt.legend()
        plt.show()
    

if __name__ == "__main__":
    protocol = "http"
    evaluator = Evaluator(protocol)
    # evaluator.flow_evaluation(
    #     f"dataset/{protocol}/{protocol}_flow_dataset.csv",
    #     # f"output/test/{protocol}_generated_flows.csv",
    #     f"output/output_dataset/{protocol}_flow_dataset.csv"
    # )
    evaluator.plot_iat_autocorrelation(
        f"dataset/{protocol}/{protocol}_flow_dataset.csv",
        f"output/output_dataset/{protocol}_flow_dataset.csv"
    )