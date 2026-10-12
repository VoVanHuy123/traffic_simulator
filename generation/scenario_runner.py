import os
import random

from scapy.all import wrpcap, Ether

from generation import GenRegistry
from generation.generator import Generator


def _ensure_ethernet(pkt):
    """Classic PCAP files carry one linktype for the whole file. Some protocol
    generators build Ether()-framed packets (arp, dhcp), others build bare
    IP-layer packets (icmp, dns, tcp, http). Wrap the bare ones in a synthetic
    Ethernet header so a merged scenario file has one consistent linktype and
    every packet decodes correctly.
    """
    if pkt.haslayer(Ether):
        return pkt
    framed = Ether() / pkt
    framed.time = pkt.time
    return framed


class ScenarioRunner:
    """Runs a scenario dict (see scenarios/loader.py) across multiple protocol
    generators and merges the resulting packets into a single PCAP, ordered
    on a shared timeline.
    """

    def __init__(self, registry=None):
        self.registry = registry or GenRegistry

    def run(self, scenario):
        base_time = random.uniform(1700000000, 1800000000)
        all_packets = []

        for comp in scenario["components"]:
            protocol = comp["protocol"]
            num_flows = comp["num_flows"]

            generator = Generator(protocol, self.registry)
            all_flows = generator.generate_flows(num_flows)

            packets = generator.generator.build_packets(all_flows, base_time)
            packets = [_ensure_ethernet(p) for p in packets]
            all_packets.extend(packets)
            print(f"[{scenario['name']}] {protocol}: {len(packets)} packets from {num_flows} flows")

        all_packets.sort(key=lambda p: p.time)

        output_path = scenario["output"]
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        wrpcap(output_path, all_packets)
        print(f"Saved {len(all_packets)} packets -> {output_path}")

        return output_path
