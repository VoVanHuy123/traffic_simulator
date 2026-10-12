import argparse
import os
import sys
import yaml
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

from scenarios.loader import list_scenarios, load_scenario, ScenarioError
from generation.scenario_runner import ScenarioRunner
from generation.protocol_spec import list_protocol_specs, load_protocol_spec, ProtocolSpecError

def generate_protocol(protocol, sample):
    generator = Generator(protocol, GenRegistry)
    all_flows = generator.generate_flows(sample)

    for index, df in enumerate(all_flows):
        print(f"== flow {index + 1} ({len(df)} packets)")
        print(df)

    generator.export_pcap(all_flows, f"output/{protocol}_flow.pcap")

def extract(protocol,input_path=None):
    input_pcap_path = f"data/{protocol}_pcap.pcap"
    rules = PROTOCOL_RULES[protocol]
    if input_path:
        input_pcap_path = input_path

    builder = FlowBuilder(ExtractRegistry)
    flows = builder.build(input_pcap_path)

    cleaner = FlowCleaner(protocol)
    flows = cleaner.clean(flows)

    extractor = Extractor(protocol)

    output_path = f"dataset/{protocol}/{protocol}_flow_dataset.csv"
    sequnces_output_path = f"dataset/{protocol}/{protocol}_sequences_dataset.csv"
    if input_path:
        output_path = f"output/output_dataset/{protocol}_flow_dataset.csv"
        sequnces_output_path = f"output/output_dataset/{protocol}_sequences_dataset.csv"


    if rules.get("stages"):
        if not input_path:
            extractor.extract_sequences_by_stages(
                flows,
                output_path
            )
    else:
        extractor.extract_flow_features(
            flows,
            sequnces_output_path
        )
    extractor.extract_sequences_features()
    
def train(protocol):
    # train flow
    flows_trainer = FlowTrainer(
        protocol=protocol,
        dataset_path=f"dataset/{protocol}/{protocol}_flow_dataset.csv",
        model_path = f"models/flow_models/{protocol}_flow.pkl"
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

def scenario_list():
    scenarios = list_scenarios()
    if not scenarios:
        print("No scenarios found in scenarios/")
        return
    for s in scenarios:
        print(f"{s['name']}: {s['description']}")

def scenario_show(name):
    try:
        scenario = load_scenario(name)
    except ScenarioError as e:
        print(f"Error: {e}")
        return
    print(yaml.safe_dump(scenario, allow_unicode=True, sort_keys=False))

def scenario_generate(name, out=None):
    try:
        scenario = load_scenario(name)
    except ScenarioError as e:
        print(f"Error: {e}")
        return
    if out:
        scenario["output"] = out
    ScenarioRunner().run(scenario)

def protocol_list():
    specs = list_protocol_specs()
    if not specs:
        print("No protocols found in protocols/")
        return
    for s in specs:
        print(f"{s['name']}: {s['description']}")

def protocol_show(name):
    try:
        spec = load_protocol_spec(name)
    except ProtocolSpecError as e:
        print(f"Error: {e}")
        return
    print(yaml.safe_dump(spec, allow_unicode=True, sort_keys=False))

def fillter(protocol,message,input_path=None):
    raw_packet_path = f"raw_data/{protocol}_dhcp.pcapng"
    if input_path:
        raw_packet_path = input_path
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
        dest="num",
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
    extract_parser.add_argument(
        "--path",
        dest="path",
        required=False,
        help="data/...."
    )

    # train command
    train_parser = subparsers.add_parser("train")
    train_parser.add_argument(
        "--p", "--protocol",
        dest="protocol",
        required=True,
        help="Protocol name (http, dns, icmp...)"
    )

    # scenario command
    scenario_parser = subparsers.add_parser("scenario")
    scenario_subparsers = scenario_parser.add_subparsers(dest="scenario_action")

    scenario_subparsers.add_parser("list")

    scenario_show_parser = scenario_subparsers.add_parser("show")
    scenario_show_parser.add_argument("--name", dest="name", required=True)

    scenario_gen_parser = scenario_subparsers.add_parser("generate")
    scenario_gen_parser.add_argument("--name", dest="name", required=True)
    scenario_gen_parser.add_argument("--out", dest="out", required=False)

    # protocol command
    protocol_parser = subparsers.add_parser("protocol")
    protocol_subparsers = protocol_parser.add_subparsers(dest="protocol_action")

    protocol_subparsers.add_parser("list")

    protocol_show_parser = protocol_subparsers.add_parser("show")
    protocol_show_parser.add_argument("--name", dest="name", required=True)

    #fillter command
    fillter_parser = subparsers.add_parser("fillter")
    fillter_parser.add_argument(
        "--m",
        "--message",
        required=True,
        dest="message",
        help="Like tshark"
    )
    fillter_parser.add_argument(
        "--l",
        "--limit",
        dest="limit"
    )
    fillter_parser.add_argument(
        "--p", "--protocol",
        dest="protocol",
        required=True,
        help="Protocol name (http, dns, icmp...)"
    )
    fillter_parser.add_argument(
        "--i", "--input",
        dest="input",
    )

    args = parser.parse_args()

    if args.command == "generate":
        generate_protocol(args.protocol,args.num)
        print("Generate traffic", args.protocol)

    elif args.command == "extract":
        if args.path:
            extract(args.protocol,args.path)
        else:
            extract(args.protocol)

    elif args.command == "train":
        train(args.protocol)

    elif args.command == "scenario":
        if args.scenario_action == "list":
            scenario_list()
        elif args.scenario_action == "show":
            scenario_show(args.name)
        elif args.scenario_action == "generate":
            scenario_generate(args.name, args.out)
        else:
            print("Usage: traffic scenario [list|show|generate] ...")

    elif args.command == "protocol":
        if args.protocol_action == "list":
            protocol_list()
        elif args.protocol_action == "show":
            protocol_show(args.name)
        else:
            print("Usage: traffic protocol [list|show] ...")

    elif args.command == "fillter":
        if args.input:
            fillter(args.protocol,args.message,args.input)

        else:
            fillter(args.protocol,args.message)


if __name__ == "__main__":
    main()