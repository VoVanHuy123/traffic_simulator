from scapy.all import ICMP
from .base import ProtocolHandler


class ICMPHandler(ProtocolHandler):

    name = "icmp"

    def match(self, pkt):
        return pkt.haslayer(ICMP)

    def build_flow_key(self, data):

        ip_pair = tuple(sorted([
            data["src_ip"],
            data["dst_ip"]
        ]))

        return ("icmp", ip_pair, data["icmp_id"])

    def is_session_start(self, pkt):

        if pkt.haslayer(ICMP):
            return pkt[ICMP].type == 8

        return False