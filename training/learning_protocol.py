import pandas as pd
import json
import os


def learn_protocol_distribution(dataset_csv, model_output="protocol_models.json"):

    df = pd.read_csv(dataset_csv)

    protocols = df["protocol"].unique()

    models = {}

    for proto in protocols:

        proto_df = df[df["protocol"] == proto]
        transport = proto_df["transport"].mode()[0]
        # port 
        service_ports = proto_df.apply(
            lambda r: min(r["src_port"], r["dst_port"]),
            axis=1
        )
        port_counts = service_ports.value_counts(normalize=True)

        ports = {}
        # common_ports = [80,8080,8000]

        for port, prob in port_counts.items():
            ports[str(int(port))] = float(prob)


        stats = {}
        stats["transport"] = transport
        stats["ports"] = ports


        numeric_cols = [
            "flow_duration",
            "packet_count",
            "total_bytes",
            "avg_packet_size",
            "min_packet_size",
            "max_packet_size",
            "std_packet_size",
            "packet_rate",
            "byte_rate",
            "fwd_packets",
            "bwd_packets",
            "fwd_bytes",
            "bwd_bytes",
            "iat_mean",
            "iat_std"
        ]

        for col in numeric_cols:

            if col not in proto_df.columns:
                continue

            stats[col] = {
                "mean": float(proto_df[col].mean()),
                "std": float(proto_df[col].std()),
                "min": float(proto_df[col].min()),
                "max": float(proto_df[col].max())
            }

        # direction ratio
        if "fwd_packets" in proto_df.columns and "bwd_packets" in proto_df.columns:

            total_fwd = proto_df["fwd_packets"].sum()
            total_bwd = proto_df["bwd_packets"].sum()

            if (total_fwd + total_bwd) > 0:
                direction_ratio = total_fwd / (total_fwd + total_bwd)
            else:
                direction_ratio = 0.5

            stats["direction_ratio"] = direction_ratio

        models[proto] = stats

    # save model
    with open(model_output, "w") as f:
        json.dump(models, f, indent=4)

    print("Protocol models saved to", model_output)

    return models
if __name__ == "__main__":
    learn_protocol_distribution(
    "dataset/http1_flow_dataset.csv",
    "models/protocol_models.json"
)