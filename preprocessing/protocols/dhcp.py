from scapy.all import BOOTP
from .base import ProtocolHandler


class DHCPHandler(ProtocolHandler):

    name = "dhcp"

    def match(self, pkt):
        return pkt.haslayer("DHCP")

    def build_flow_key(self, data):
        return (self.name, data["xid"])

    def is_session_start(self, pkt):

        for opt in pkt["DHCP"].options:
            if isinstance(opt, tuple) and opt[0] == "message-type":
                return opt[1] == 1  # Discover

    def validate_flow(self, flow,rules):

        states = []

        for pkt in flow["packets"]:
            for opt in pkt["DHCP"].options:
                if isinstance(opt, tuple) and opt[0] == "message-type":
                    states.append(opt[1])
        required = rules.get("cleaning_rules").get("required_states", [])
        return all(x in states for x in required)

    def extract_flags(self, pkt):

        for opt in pkt["DHCP"].options:
            if isinstance(opt, tuple) and opt[0] == "message-type":
                return {"dhcp_msg_type": opt[1]}

        return {}
    def extract_direction(pkt,data=None):
        sport = pkt["UDP"].sport
        dport = pkt["UDP"].dport

        if sport == 68 and dport == 67:
            return {"direction" : 0}
        elif sport == 67 and dport == 68:
            return {"direction" : 1}
        