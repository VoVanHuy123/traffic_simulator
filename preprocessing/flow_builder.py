from scapy.all import rdpcap
from .packet_parser import PacketParser


class FlowBuilder:

    def __init__(self, registry):
        self.registry = registry
        self.parser = PacketParser()
        self.active = {}

    def build(self, pcap):

        packets = rdpcap(pcap)
        packets = sorted(packets, key=lambda x: x.time)

        flows = []

        for pkt in packets:

            handler = self.registry.get_handler(pkt)

            if not handler:
                continue

            data = self.parser.parse(pkt)

            key = handler.build_flow_key(data)

            if handler.is_session_start(pkt) or key not in self.active:

                flow = {
                    "protocol": handler.name,
                    "handler": handler,
                    "key_dict": data,
                    "packets": []
                }

                self.active[key] = flow
                flows.append(flow)

            self.active[key]["packets"].append(pkt)

        return flows