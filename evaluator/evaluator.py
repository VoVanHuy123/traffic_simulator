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

            os.makedirs(f"evaluator/output/{self.protocol}", exist_ok=True)
            plt.tight_layout()
            plt.savefig(f"evaluator/output/{self.protocol}/compare_{feature}.png")
            plt.close()

    def flow_evaluation_two_way(self, real_flows_path, old_flows_path, new_flows_path):
        real_df = pd.read_csv(real_flows_path)
        old_df = pd.read_csv(old_flows_path)
        new_df = pd.read_csv(new_flows_path)

        features = [f for f in self.rules.get("evaluation_features") if f in real_df.columns]
        features = [f for f in features if f in old_df.columns and f in new_df.columns]

        output_dir = f"evaluator/output/{self.protocol}"
        os.makedirs(output_dir, exist_ok=True)

        report_lines = [f"Two-way evaluation for protocol={self.protocol}", ""]
        for feature in features:
            report_lines.append(f"Feature: {feature}")
            report_lines.append(self._feature_summary_line(feature, real_df, old_df, new_df))
            report_lines.append(self._feature_ks_line(feature, real_df, old_df, new_df))
            report_lines.append(self._feature_js_line(feature, real_df, old_df, new_df))
            report_lines.append("")
            self._plot_two_way_histogram(feature, old_df, new_df, output_dir)

        report_path = f"{output_dir}/{self.protocol}_two_way_report.txt"
        with open(report_path, "w", encoding="utf-8") as report_file:
            report_file.write("\n".join(report_lines))

        print(f"Saved evaluation report: {report_path}")
        return report_path
    def flow_evaluation_three_way(self, real_flows_path, old_flows_path, new_flows_path):
        real_df = pd.read_csv(real_flows_path)
        old_df = pd.read_csv(old_flows_path)
        new_df = pd.read_csv(new_flows_path)

        features = [f for f in self.rules.get("evaluation_features") if f in real_df.columns]
        features = [f for f in features if f in old_df.columns and f in new_df.columns]

        output_dir = f"evaluator/output/{self.protocol}"
        os.makedirs(output_dir, exist_ok=True)

        report_lines = [f"Three-way evaluation for protocol={self.protocol}", ""]
        for feature in features:
            report_lines.append(f"Feature: {feature}")
            report_lines.append(self._feature_summary_line(feature, real_df, old_df, new_df))
            report_lines.append(self._feature_ks_line(feature, real_df, old_df, new_df))
            report_lines.append(self._feature_js_line(feature, real_df, old_df, new_df))
            report_lines.append("")
            self._plot_three_way_histogram(feature, real_df, old_df, new_df, output_dir)

        report_path = f"{output_dir}/{self.protocol}_compare_real_report.txt"
        with open(report_path, "w", encoding="utf-8") as report_file:
            report_file.write("\n".join(report_lines))

        print(f"Saved evaluation report: {report_path}")
        return report_path

    def _feature_summary_line(self, feature, real_df, old_df, new_df):
        real_mean = real_df[feature].mean()
        old_mean = old_df[feature].mean()
        new_mean = new_df[feature].mean()
        delta_old = old_mean - real_mean
        delta_new = new_mean - real_mean
        return (
            f"    real_mean={real_mean:.4f}, old_mean={old_mean:.4f}, new_mean={new_mean:.4f}, "
            f"delta_old={delta_old:.4f}, delta_new={delta_new:.4f}"
        )

    def _feature_ks_line(self, feature, real_df, old_df, new_df):
        ks_old = ks_2samp(real_df[feature], old_df[feature])
        ks_new = ks_2samp(real_df[feature], new_df[feature])
        return (
            f"    KS real-old: statistic={ks_old.statistic:.4f}, pvalue={ks_old.pvalue:.4f}; "
            f"KS real-new: statistic={ks_new.statistic:.4f}, pvalue={ks_new.pvalue:.4f}"
        )

    def _feature_js_line(self, feature, real_df, old_df, new_df):
        dist_old = self._jensen_shannon_distance(real_df[feature], old_df[feature])
        dist_new = self._jensen_shannon_distance(real_df[feature], new_df[feature])
        return f"    JS real-old={dist_old:.4f}, JS real-new={dist_new:.4f}"

    def _plot_three_way_histogram(self, feature, real_df, old_df, new_df, output_dir):
        plt.figure(figsize=(8,5))
        sns.histplot(
            real_df[feature],
            color="blue",
            label="REAL",
            stat="density",
            bins=50,
            kde=True,
            alpha=0.4
        )
        sns.histplot(
            old_df[feature],
            color="orange",
            label="OLD",
            stat="density",
            bins=50,
            kde=True,
            alpha=0.4
        )
        sns.histplot(
            new_df[feature],
            color="red",
            label="NEW",
            stat="density",
            bins=50,
            kde=True,
            alpha=0.4
        )
        plt.title(f"Real / Old / New Distribution: {feature}")
        plt.xlabel(feature)
        plt.ylabel("Density")
        plt.legend()
        plt.tight_layout()
        plt.savefig(f"{output_dir}/compare_three_{feature}.png")
        plt.close()

    def _plot_two_way_histogram(self, feature, old_df, new_df, output_dir):
        plt.figure(figsize=(8,5))
        sns.histplot(
            old_df[feature],
            color="orange",
            label="OLD",
            stat="density",
            bins=50,
            kde=True,
            alpha=0.4
        )
        sns.histplot(
            new_df[feature],
            color="red",
            label="NEW",
            stat="density",
            bins=50,
            kde=True,
            alpha=0.4
        )
        plt.title(f"Old / New Distribution: {feature}")
        plt.xlabel(feature)
        plt.ylabel("Density")
        plt.legend()
        plt.tight_layout()
        plt.savefig(f"{output_dir}/compare_two_{feature}.png")
        plt.close()

    def _jensen_shannon_distance(self, real_series, sim_series):
        real_series = real_series.dropna()
        sim_series = sim_series.dropna()
        if real_series.empty or sim_series.empty:
            return float('nan')

        min_value = min(real_series.min(), sim_series.min())
        max_value = max(real_series.max(), sim_series.max())
        if min_value == max_value:
            return 0.0

        bins = np.linspace(min_value, max_value, 51)
        real_hist, _ = np.histogram(real_series, bins=bins, density=True)
        sim_hist, _ = np.histogram(sim_series, bins=bins, density=True)
        real_hist = real_hist + 1e-12
        sim_hist = sim_hist + 1e-12
        return jensenshannon(real_hist, sim_hist)

    def plot_iat_autocorrelation(self, real_flows_path, sim_flows_path):
        real_df = pd.read_csv(real_flows_path)
        sim_df = pd.read_csv(sim_flows_path)
        real_iat = real_df.get("iat_mean")
        sim_iat = sim_df.get("iat_mean")

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
    evaluator.flow_evaluation_three_way(
        f"dataset/{protocol}/{protocol}_flow_dataset.csv",
        f"output/compare_{protocol}/{protocol}_flows_old.csv",
        f"output/compare_{protocol}/{protocol}_flows_new.csv"
    )
    # evaluator.plot_iat_autocorrelation(
    #     f"dataset/{protocol}/{protocol}_flow_dataset.csv",
    #     f"output/compare_http/{protocol}_flows_new.csv"
    #     # f"output/output_dataset/{protocol}_flow_dataset.csv"
    # )