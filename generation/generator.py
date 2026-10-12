import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from generation.protocol_spec import load_protocol_spec
from generation.declarative_generator import generate_flow_sequence


class Generator:
    def __init__(self, protocol, registry):
        self.registry = registry
        self.protocol = protocol
        self.spec = load_protocol_spec(protocol)
        self.generator = self.registry.get_generator_handler(self.protocol)

    def generate_flows(self, num_flows):
        """Return `num_flows` independent per-packet sequence DataFrames, built
        directly from the protocol's declared spec (protocols/<name>.yaml) --
        no trained model, no dataset, no collect/extract/train step needed."""
        return [generate_flow_sequence(self.protocol, self.spec) for _ in range(num_flows)]

    def export_pcap(self, all_flows, output_path):
        self.generator.to_pcap(all_flows, output_path)
