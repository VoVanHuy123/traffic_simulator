import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import numpy as np
from rules.protocol_rules import PROTOCOL_RULES
class FlowCleaner:
    def __init__(self,proto):
        self.proto =proto
    rules = {}
    def clean(self, flows):

        cleaned = []
        self.rules = PROTOCOL_RULES[self.proto].get("cleaning_rules", {})

        for flow in flows:

            handler = flow["handler"]
            packets = flow["packets"]
            if len(packets) < 2:
                continue

            # -------------------------
            # Duration check
            # -------------------------
            times = [pkt.time for pkt in packets]
            duration = times[-1] - times[0]

            if duration > self.rules.get("max_flow_duration", 999):
                continue

            # -------------------------
            # IAT check
            # -------------------------
            iats = np.diff(times)

            if len(iats) > 0:
                if max(iats) > self.rules.get("max_iat", 999):
                    continue

            # -------------------------
            # Min packet
            # -------------------------
            if len(packets) < self.rules.get("min_packets", 1):
                continue

            if handler.validate_flow(flow,self.rules):
                cleaned.append(flow)

        return cleaned