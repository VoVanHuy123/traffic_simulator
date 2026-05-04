from .base import ProtocolHandler

ISUP_MSG_TYPES = {
    1: "IAM",
    2: "ACM",
    3: "ANM",
    5: "REL",
    6: "RLC",
    7: "RSC",
    16: "COT"
}


def get_isup_msg_name(value):
    if value is None:
        return None
    if isinstance(value, str):
        return value
    try:
        return ISUP_MSG_TYPES.get(int(value), str(value))
    except Exception:
        return str(value)


class ISUPHandler(ProtocolHandler):

    name = "isup"

    def match(self, pkt):
        return pkt.haslayer("ISUP")

    def build_flow_key(self, data):
        session_id = data.get("isup_session_id")
        if session_id:
            return (self.name, session_id)

        if data.get("opc") is not None and data.get("dpc") is not None and data.get("cic") is not None:
            return (
                self.name,
                data.get("opc"),
                data.get("dpc"),
                data.get("cic")
            )

        return (
            self.name,
            data.get("src_ip"),
            data.get("dst_ip"),
            data.get("src_port"),
            data.get("dst_port")
        )

    def is_session_start(self, pkt):
        if not pkt.haslayer("ISUP"):
            return False

        isup = pkt["ISUP"]
        msg = getattr(isup, "msg_type", None) or getattr(isup, "message_type", None)
        msg_name = get_isup_msg_name(msg)
        return msg_name == "IAM"

    def validate_flow(self, flow, rules=None):
        packets = flow["packets"]
        return len(packets) >= rules.get("cleaning_rules", {}).get("min_packets", 1)

    def extract_flags(self, pkt):
        if not pkt.haslayer("ISUP"):
            return {}

        isup = pkt["ISUP"]
        msg = getattr(isup, "msg_type", None) or getattr(isup, "message_type", None)
        return {"isup_msg_type": get_isup_msg_name(msg)}

    def extract_direction(self, pkt, data=None):
        if data and data.get("src_ip"):
            return super().extract_direction(pkt, data)

        return {"direction": 0}

    def get_stage_name(self, msg_type):
        msg_name = get_isup_msg_name(msg_type)
        if msg_name in ["IAM", "ACM"]:
            return "setup"
        if msg_name == "ANM":
            return "active"
        if msg_name in ["REL", "RLC"]:
            return "cleanup"
        return None

    def get_ptks_by_stages(self, flow):
        packets = sorted(flow["packets"], key=lambda x: x.time)
        stages = {"setup": [], "active": [], "cleanup": []}

        for pkt in packets:
            if not pkt.haslayer("ISUP"):
                continue

            isup = pkt["ISUP"]
            msg = getattr(isup, "msg_type", None) or getattr(isup, "message_type", None)
            stage = self.get_stage_name(msg)
            if stage:
                stages[stage].append(pkt)

        return stages
