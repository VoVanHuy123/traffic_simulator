from scapy.all import TCP
from .base import ProtocolHandler


class TCPHandler(ProtocolHandler):

    name = "tcp"

    def match(self, pkt, data):
        return data["protocol"] in ["tcp", "http", "https"]


    def build_flow_key(self, data):

        ep1, ep2 = self.normalize(data)

        return (
            data["protocol"],
            ep1,
            ep2,
            data["transport"]
        )

    def is_session_start(self, pkt):

        if not pkt.haslayer(TCP):
            return False

        flags = pkt[TCP].flags
        return (flags & 0x02) and not (flags & 0x10)

    def validate_flow(self, flow, rules):

        packets = flow["packets"]
        max_packets = rules.get("max_packets", 50)
        if len(packets) > max_packets:
            packets = packets[:max_packets]
            flow["packets"] = packets

        first = packets[0]

        if first.haslayer(TCP):
            flags = first[TCP].flags
            return (flags & 0x02) and not (flags & 0x10)

        return True
    def extract_flags(self, pkt):
        if TCP in pkt:
            return{"tcp_flags" : int(pkt[TCP].flags)}
    
    def get_ptks_by_handshake_stage(self,flow):
        handshake = []
        packets = sorted(flow["packets"], key=lambda x: x.time)
        for i in range(len(packets)):
            pkt = packets[i]

            if pkt.haslayer(TCP):
                flags = int(pkt[TCP].flags)

                # SYN (no ACK)
                if (flags & 0x02) and not (flags & 0x10):
                    handshake = packets[i:i+3]
                    break

        if len(handshake) == 3:
            return {"handshake" : handshake}
        else:
            return {"handshake" : []}
    def get_ptks_by_closing_stage(self,flow):
        closing = []
        packets = sorted(flow["packets"], key=lambda x: x.time)

        for i in range(len(packets)):
            pkt = packets[i]

            if pkt.haslayer(TCP):
                flags = int(pkt[TCP].flags)

                if flags & 0x01:  # FIN
                    closing = packets[i:i+4]
                    break

        if len(closing) >= 1:
           return{"closing" : closing}
        else: return{"closing" : []}


class HTTPHandler(TCPHandler):
    name = "http"
    def match(self, pkt):
        if pkt.haslayer(TCP):
            s_port = pkt[TCP].sport
            d_port = pkt[TCP].dport
            if s_port == 80 or d_port == 80:
                return True
            else:
                return False
            
    def get_ptks_by_stages(self,flow):
        stage_pkts = {}

        handshake_stage = self.get_ptks_by_handshake_stage(flow)
        closing_stage = self.get_ptks_by_closing_stage(flow)

        stage_pkts.update(handshake_stage)
        stage_pkts.update(closing_stage)
        
        packets = sorted(flow["packets"], key=lambda x: x.time)

        data = []
        start = 0
        end = len(packets)
        if handshake_stage.get("handshake"):
            start = packets.index(handshake_stage["handshake"][-1]) + 1
        if closing_stage.get("closing"):
            end = packets.index(closing_stage["closing"][0])
        if start < end:
            data = packets[start:end]
        if len(data) > 0:
            stage_pkts["data"] = data
        else: stage_pkts["data"] = []

        return stage_pkts