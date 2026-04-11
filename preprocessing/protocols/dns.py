from .base import ProtocolHandler


class DNSHandler(ProtocolHandler):

    name = "dns"

    def match(self, pkt):
        return pkt.haslayer("DNS")

    def build_flow_key(self, data):
        ep1, ep2 = self.normalize(data)

        return (
            "dns",
            ep1,
            ep2,
            data.get("id")
        )

    def is_session_start(self, pkt):
        return pkt["DNS"].qr == 0

    def validate_flow(self, flow,rules=None):

        has_q = False
        has_r = False

        for pkt in flow["packets"]:
            dns = pkt["DNS"]
            if dns.qr == 0:
                has_q = True
            else:
                has_r = True

        return has_q and has_r

    def extract_flags(self, pkt):
        return {"dns_type": pkt["DNS"].qr}