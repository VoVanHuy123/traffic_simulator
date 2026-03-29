import argparse
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from rules.protocol_rules import PROTOCOL_RULES

from training.flow_training import FlowTrainer
from training.sequences_training import SequenceHMMTrainer

from generation import GenRegistry
from generation.generator import Generator

from preprocessing import ExtractRegistry
from preprocessing.flow_builder import FlowBuilder
from preprocessing.flow_cleaner import FlowCleaner
from preprocessing.extractor import Extractor

from data_fillter.fillter import PcapFillter

def generate_protocol(protocol, sample):
    # protocol = "dns"

    generator = Generator(protocol,GenRegistry)
    df_flows = generator.generate_flows_features(sample)

    all_flows = []
    for index, row in df_flows.iterrows():
        print(f"== flow {index +1}")
        df = generator.generate_sequences_features(row["packet_count"])
        all_flows.append(df)
        print(df)
    
    generator.export_pcap(all_flows,f"output/{protocol}_flow.pcap")

def extract(protocol):
    input_pcap_path = f"data/{protocol}_pcap.pcap"

    builder = FlowBuilder(ExtractRegistry)
    flows = builder.build(input_pcap_path)

    cleaner = FlowCleaner(protocol)
    flows = cleaner.clean(flows)

    extractor = Extractor(protocol)

    extractor.extract_flow_features(
        flows,
        f"dataset/{protocol}_flow_dataset.csv"
    )

    extractor.extract_sequences_by_stages(
        flows,
        "ff"
    )
def train(protocol):
    # train flow
    flows_trainer = FlowTrainer(
        protocol=protocol,
        dataset_path=f"dataset/{protocol}_flow_dataset.csv",
        model_path=f"dataset/{protocol}_flow_dataset.csv"
    )
    flows_trainer.model_train()

    # train sequences
    sequences_trainer = SequenceHMMTrainer(
        protocol=protocol,
        rules=PROTOCOL_RULES[protocol]
    )
    have_stages = PROTOCOL_RULES[protocol].get("stages")
    if have_stages:
        sequences_trainer.train_by_stage()
    else:
        sequences_trainer.train()

def fillter(protocol,message):
    raw_packet_path = f"raw_data/{protocol}_dhcp.pcapng"
    output_pcap = f"data/{protocol}_pcap.pcap" 
    fillter = PcapFillter()
    fillter.filter_packets_pcap(raw_packet_path, output_pcap, protocol=message)

def main():

    parser = argparse.ArgumentParser("traffic")

    subparsers = parser.add_subparsers(dest="command")

    # generate command
    gen_parser = subparsers.add_parser("generate")
    gen_parser.add_argument(
        "-p", "--protocol",
        dest="protocol",
        required=True,
        help="Protocol name (http, dns, icmp...)"
    )
    gen_parser.add_argument(
        "--n",
        "--num",
        type=int,
        default=10)
    
    #extract command
    extract_parser = subparsers.add_parser("extract")
    extract_parser.add_argument(
        "--p", "--protocol",
        dest="protocol",
        required=True,
        help="Protocol name (http, dns, icmp...)"
    )

    # train command
    train_parser = subparsers.add_parser("train")
    train_parser.add_argument(
        "--p", "--protocol",
        dest="protocol",
        required=True,
        help="Protocol name (http, dns, icmp...)"
    )

    #fillter command
    fillter_parser = subparsers.add_parser("fillter")
    fillter_parser.add_argument(
        "--m",
        "--messeage",
        required=True,
        help="Like tshark"
    )
    fillter_parser.add_argument(
        "--l",
        "--limit",
    )
    fillter_parser.add_argument(
        "--p", "--protocol",
        dest="protocol",
        required=True,
        help="Protocol name (http, dns, icmp...)"
    )

    args = parser.parse_args()

    if args.command == "generate":
        generate_protocol(args.protocol,args.num)
        print("Generate traffic", args.protocol)

    elif args.command == "train":
        print("Train model", args.protocol)

    elif args.command == "extract":
        extract(args.protocol)

    elif args.command == "train":
        train(args.protocol)


if __name__ == "__main__":
    main()