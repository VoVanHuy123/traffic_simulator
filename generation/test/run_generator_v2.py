import argparse
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from rules.protocol_rules import PROTOCOL_RULES

from generation import GenRegistry
from generation.test.generator_v2 import GeneratorV2


def generate_protocol(protocol, sample):
    generator = GeneratorV2(protocol, GenRegistry)
    df_flows = generator.generate_flows_features(sample)

    all_flows = []
    for index, row in df_flows.iterrows():
        print(f"== flow {index + 1}")
        df = generator.generate_sequences_features(row)
        all_flows.append(df)
        print(df)

    output_dir = f"output/{protocol}_v2"
    os.makedirs(output_dir, exist_ok=True)
    generator.export_pcap(all_flows, f"{output_dir}/{protocol}_flow_v2.pcap")
    df_flows.to_csv(f"{output_dir}/{protocol}_flow_features_v2.csv", index=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser("traffic_v2")

    parser.add_argument(
        "-p", "--protocol",
        dest="protocol",
        required=True,
        help="Protocol name (http, dns, icmp...)"
    )
    parser.add_argument(
        "--n",
        "--num",
        dest="num",
        type=int,
        default=10
    )

    args = parser.parse_args()
    generate_protocol(args.protocol, args.num)
