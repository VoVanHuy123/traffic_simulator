import argparse
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import numpy as np
import pandas as pd
from generation import GenRegistry
from generation.generator import Generator as GeneratorV1
from generation.test.generator_v2 import GeneratorV2


def compare_protocol(protocol, sample):
    np.random.seed(42)

    g1 = GeneratorV1(protocol, GenRegistry)
    g2 = GeneratorV2(protocol, GenRegistry)

    df_old = g1.generate_flows_features(sample)
    df_new = g2.generate_flows_features(sample)

    old_flows = []
    new_flows = []

    for _, row in df_old.iterrows():
        old_flows.append(g1.generate_sequences_features(row["packet_count"]))

    for _, row in df_new.iterrows():
        new_flows.append(g2.generate_sequences_features(row))

    output_dir = f"output/compare_{protocol}"
    os.makedirs(output_dir, exist_ok=True)

    old_flow_csv = f"{output_dir}/{protocol}_flows_old.csv"
    new_flow_csv = f"{output_dir}/{protocol}_flows_new.csv"
    df_old.to_csv(old_flow_csv, index=False)
    df_new.to_csv(new_flow_csv, index=False)

    g1.export_pcap(old_flows, f"{output_dir}/{protocol}_flow_old.pcap")
    g2.export_pcap(new_flows, f"{output_dir}/{protocol}_flow_new.pcap")

    compare_report = create_compare_report(df_old, df_new)
    with open(f"{output_dir}/{protocol}_compare_report.txt", "w", encoding="utf-8") as report:
        report.write(compare_report)

    print(f"Comparison complete for protocol={protocol}, sample={sample}")
    print(f"Old flow CSV: {old_flow_csv}")
    print(f"New flow CSV: {new_flow_csv}")
    print(f"PCAP old: {output_dir}/{protocol}_flow_old.pcap")
    print(f"PCAP new: {output_dir}/{protocol}_flow_new.pcap")
    print(f"Report: {output_dir}/{protocol}_compare_report.txt")
    print(compare_report)


def create_compare_report(df_old, df_new):
    metrics = ["packet_count", "flow_duration", "avg_packet_size", "total_bytes", "iat_mean"]
    report = []
    report.append("Feature comparison summary\n")
    report.append("============================\n")

    valid_metrics = [m for m in metrics if m in df_old.columns and m in df_new.columns]
    if valid_metrics:
        for feature in valid_metrics:
            old_mean = df_old[feature].mean()
            new_mean = df_new[feature].mean()
            diff = new_mean - old_mean
            report.append(f"{feature}: old mean={old_mean:.4f}, new mean={new_mean:.4f}, delta={diff:.4f}\n")
    else:
        report.append("No common numeric features found for direct comparison.\n")

    report.append("\nOld feature statistics:\n")
    old_metrics = [m for m in metrics if m in df_old.columns]
    if old_metrics:
        report.append(df_old[old_metrics].describe().to_string())
    else:
        report.append("No matching features in old flow dataset.\n")

    report.append("\nNew feature statistics:\n")
    new_metrics = [m for m in metrics if m in df_new.columns]
    if new_metrics:
        report.append(df_new[new_metrics].describe().to_string())
    else:
        report.append("No matching features in new flow dataset.\n")

    return "\n".join(report)


if __name__ == "__main__":
    # parser = argparse.ArgumentParser("compare_generator")
    # parser.add_argument(
    #     "-p", "--protocol",
    #     dest="protocol",
    #     required=True,
    #     help="Protocol name (http, dns, icmp...)"
    # )
    # parser.add_argument(
    #     "--n",
    #     "--num",
    #     dest="num",
    #     type=int,
    #     default=10
    # )
    # args = parser.parse_args()
    protocol = "http"
    num= 90
    compare_protocol(protocol,num)
    # compare_protocol(args.protocol, args.num)
