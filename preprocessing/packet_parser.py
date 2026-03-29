from scapy.all import IP, TCP, UDP, BOOTP,ICMP


class PacketParser:

    def detect_protocol(self,pkt):

        if pkt.haslayer(TCP):

            sport = pkt[TCP].sport
            dport = pkt[TCP].dport

            if sport == 80 or dport == 80:
                return "HTTP"

            if sport == 443 or dport == 443:
                return "HTTPS"

            if sport == 53 or dport == 53:
                return "DNS"

            return "TCP"

        elif pkt.haslayer(UDP):

            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

            if sport == 53 or dport == 53:
                return "DNS"

            if sport == 67 or dport == 68:
                return "DHCP"

            return "UDP"
        elif pkt.haslayer(ICMP):

            return "ICMP"

        return "OTHER"
    def parse(self, pkt):

        # data = {}

        # if IP in pkt:
        #     data["src_ip"] = pkt[IP].src
        #     data["dst_ip"] = pkt[IP].dst

        # if TCP in pkt:
        #     data["src_port"] = pkt[TCP].sport
        #     data["dst_port"] = pkt[TCP].dport
        #     data["transport"]= "TCP"

        # if UDP in pkt:
        #     data["src_port"] = pkt[UDP].sport
        #     data["dst_port"] = pkt[UDP].dport
        #     data["transport"]= "UDP"

        # if pkt.haslayer("DNS"):
        #     data["dns_id"] = pkt["DNS"].id

        # if pkt.haslayer(BOOTP):
        #     data["xid"] = pkt[BOOTP].xid
        # if pkt.haslayer(ICMP):
        #     data["transport"]= "ICMP"
        #     data["icmp_id"]= pkt[ICMP].id
        # data["protocol"] = self.detect_protocol(pkt).lower()
        # return data
        data = {
            "src_ip": None,
            "dst_ip": None,
            "src_port": 0,
            "dst_port": 0,
            "transport": None,
            "protocol": None,
            "xid": None,
            "id": None,
            "icmp_id": None
        }

        # DHCP
        if pkt.haslayer(BOOTP):
            data.update({
                "protocol": "dhcp",
                "xid": pkt[BOOTP].xid
            })

        # ARP
        elif pkt.haslayer("ARP"):
            data.update({
                "src_ip": pkt["ARP"].psrc,
                "dst_ip": pkt["ARP"].pdst,
                "transport": "ARP",
                "protocol": "arp"
            })
        
        # IP
        elif pkt.haslayer(IP):
            ip = pkt[IP]

            data["src_ip"] = ip.src
            data["dst_ip"] = ip.dst

            if pkt.haslayer(TCP):
                data.update({
                    "src_port": pkt[TCP].sport,
                    "dst_port": pkt[TCP].dport,
                    "transport": "TCP"
                })

            elif pkt.haslayer(UDP):
                data.update({
                    "src_port": pkt[UDP].sport,
                    "dst_port": pkt[UDP].dport,
                    "transport": "UDP"
                })

            elif pkt.haslayer(ICMP):
                data.update({
                    "transport": "ICMP",
                    "protocol": "icmp",
                    "icmp_id": pkt[ICMP].id
                })

            data["protocol"] = data["protocol"] or self.detect_protocol(pkt).lower()

            if pkt.haslayer("DNS"):
                data["id"] = pkt["DNS"].id

        return data