from .base import ProtocolHandler


class ARPHandler(ProtocolHandler):

    name = "arp"

    def match(self, pkt):
        return pkt.haslayer("ARP")

    def build_flow_key(self, data):

        ip1 = data["src_ip"]
        ip2 = data["dst_ip"]

        ip_pair = tuple(sorted([ip1, ip2]))

        return (
            self.name,
            ip_pair
        )

    def is_session_start(self, pkt):
        return pkt.haslayer("ARP") and pkt["ARP"].op == 1

    def validate_flow(self, flow,rules=None):
        return True

    def extract_flags(self, pkt):
        if pkt.haslayer("ARP"):
         return {"arp_opcode" : pkt["ARP"].op}
    def extract_direction(pkt,data=None):
        direction = 0
        src = pkt["ARP"].psrc
        direction = 0 if src == data["src_ip"] else 1

        return {"direction" : direction}