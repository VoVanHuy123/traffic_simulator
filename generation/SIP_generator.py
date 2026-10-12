import random
import numpy as np
from scapy.all import IP, UDP, Raw
from .base_generator import BaseFlowGenerator

SIP_USERS = ["alice", "bob", "carol", "dave", "eve"]
SIP_REASON = {"100": "Trying", "180": "Ringing", "200": "OK"}


class SIPFlowGenerator(BaseFlowGenerator):
    protocol = "sip"

    def build_sip_message(self, method, call_id, cseq, from_user, to_user, from_ip, to_ip, min_size):
        if method in ("INVITE", "ACK", "BYE"):
            start_line = f"{method} sip:{to_user}@{to_ip} SIP/2.0"
            cseq_method = method
        else:
            start_line = f"SIP/2.0 {method} {SIP_REASON.get(method, 'OK')}"
            cseq_method = "INVITE"

        lines = [
            start_line,
            f"Via: SIP/2.0/UDP {from_ip}:5060",
            f"From: <sip:{from_user}@{from_ip}>;tag={random.randint(1000, 9999)}",
            f"To: <sip:{to_user}@{to_ip}>",
            f"Call-ID: {call_id}",
            f"CSeq: {cseq} {cseq_method}",
            "Content-Length: 0",
            "",
            "",
        ]
        payload = "\r\n".join(lines).encode()
        if len(payload) < min_size:
            payload += b"a" * (min_size - len(payload))
        return payload

    def build_packets(self, all_df, base_time):
        packets = []
        time = base_time

        for df in all_df:
            client_ip = f"192.168.1.{np.random.randint(1, 100)}"
            server_ip = f"192.168.1.{np.random.randint(1, 100)}"
            from_user = random.choice(SIP_USERS)
            to_user = random.choice([u for u in SIP_USERS if u != from_user])
            call_id = f"{random.randint(10**8, 10**9)}@{client_ip}"
            cseq = random.randint(1, 100)

            for row in df.to_dict("records"):
                time += float(row["iat"])

                direction = int(row["direction"])
                method = str(row["sip_method"])
                pkt_len = int(row["packet_length"])

                if direction == 0:
                    sip, dip = client_ip, server_ip
                else:
                    sip, dip = server_ip, client_ip

                payload = self.build_sip_message(method, call_id, cseq, from_user, to_user, sip, dip, pkt_len)

                pkt = IP(src=sip, dst=dip) / UDP(sport=5060, dport=5060) / Raw(load=payload)
                pkt.time = time
                packets.append(pkt)

        return packets
