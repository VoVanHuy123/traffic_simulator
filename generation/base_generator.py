import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import random
from scapy.all import wrpcap


class BaseFlowGenerator:
    protocol = ""

    def match(self, protocol):
        return self.protocol == protocol

    def build_packets(self, all_df, base_time):
        """Build the list of Scapy packets for this protocol without writing a file.

        `all_df` is a list of per-flow sequence DataFrames, each produced by
        generation/declarative_generator.py from this protocol's declared
        spec (protocols/<name>.yaml) -- no trained model involved.

        `base_time` is the shared timeline origin so multiple protocols can be
        merged into one PCAP (see generation/scenario_runner.py) with a
        consistent, interleavable timestamp axis.
        """
        raise NotImplementedError

    def to_pcap(self, all_df, filename):
        base_time = random.uniform(1700000000, 1800000000)
        packets = self.build_packets(all_df, base_time)
        wrpcap(filename, packets)
        print(f"Saved {filename}")
