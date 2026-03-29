from scapy.all import IP, IPv6
import numpy as np
class ProtocolHandler:

    name = "base"

    def match(self, pkt):
        raise NotImplementedError
    def normalize(self, data):
        ep1 = (data["src_ip"], data["src_port"])
        ep2 = (data["dst_ip"], data["dst_port"])

        return (ep1, ep2) if ep1 <= ep2 else (ep2, ep1)
    def build_flow_key(self, data):
        raise NotImplementedError

    def is_session_start(self, pkt):
        return False

    def validate_flow(self, flow):
        return True

    def extract_flags(self, pkt):
        return {}
    def extract_direction(self,pkt,data=None):
        direction=0
        src = 0
        if "src_ip" in data:
            if IP in pkt:
                src = pkt[IP].src
            elif IPv6 in pkt:
                src = pkt["IPv6"].src
            else:
                direction = 0
        direction = 0 if src == data.get("src_ip") else 1
        return {"direction" : direction}
    