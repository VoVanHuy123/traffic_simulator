import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import numpy as np
import pandas as pd
from scapy.all import IP, UDP, DNS,DNSQR,DNSRR,Raw,DHCP,BOOTP,RandMAC,mac2str,Ether
import random
import time
from .base_generator import BaseFlowGenerator
from rules.protocol_rules import DNS_DATA
class UDPFlowGenerator(BaseFlowGenerator):
    protocol = "udp"
    def sss():
        pass


class DNSFlowGenerator(UDPFlowGenerator):
    protocol = "dns"
    def random_domain(self):
        domains = DNS_DATA.get("domains")
        domain = random.choice(domains)
        return domain

    def random_dns_type(self, dns_type):
        # map flag → DNS type
        mapping = {
            1: "A",
            2: "AAAA",
            3: "MX",
            4: "NS"
        }
        return mapping.get(dns_type, "A")

    def build_packets(self, all_df, base_time):

        packets = []
        time = base_time

        for df in all_df:

            # random IP
            client_ip = f"192.168.1.{np.random.randint(1, 100)}"
            server_ip = "8.8.8.8"  # DNS server

            client_port = np.random.randint(1024, 65535)
            server_port = 53

            dns_id = np.random.randint(0, 65535)

            domain = self.random_domain()
            query_name = domain.get("domain")
            rdata = random.choice(domain.get("ips"))

            for row in df.to_dict("records"):

                time += float(row["iat"])

                direction = int(row["direction"])
                dns_type_flag = int(row["dns_type"])
                pkt_len = int(row["packet_length"])

                dns_type = self.random_dns_type(dns_type_flag)

                # -------- CLIENT → DNS QUERY --------
                if direction == 0:
                    pkt = IP(src=client_ip, dst=server_ip) / \
                          UDP(sport=client_port, dport=server_port) / \
                          DNS(
                              id=dns_id,
                              qr=0,  # query
                              qd=DNSQR(qname=query_name, qtype=dns_type)
                          )

                # -------- SERVER → DNS RESPONSE --------
                else:
                    pkt = IP(src=server_ip, dst=client_ip) / \
                          UDP(sport=server_port, dport=client_port) / \
                          DNS(
                              id=dns_id,
                              qr=1,  # response
                              aa=1,
                              qd=DNSQR(qname=query_name, qtype=dns_type),
                              an=DNSRR(
                                  rrname=query_name,
                                  type=dns_type,
                                  ttl=300,
                                  rdata=rdata
                              )
                          )
                
                current_len = len(pkt)

                if current_len < pkt_len:
                    if pkt_len > 1100:
                        pkt_len = np.random.randint(400, 600) 
                    padding_size = pkt_len - current_len
                    pkt = pkt / Raw(load=b"A" * padding_size)

                pkt.time = time
                packets.append(pkt)

        return packets



class DHCPFlowGenerator(UDPFlowGenerator):
    protocol = "dhcp"
    def build_packets(self, flows, base_time):

        packets = []
        current_time = base_time



        client_ip = "192.168.1.2"
        server_ip = "192.168.1.1"

# nếu truyền 1 dataframe
        if isinstance(flows, pd.DataFrame):
            flows = [flows]

        for df in flows:

            xid = random.randint(1, 0xFFFFFFFF)
            client_mac = RandMAC()
            server_mac = RandMAC()
            for _, row in df.iterrows():
                direction = row["direction"]
                dhcp_type = row["dhcp_msg_type"]
                pkt_len = row["packet_length"]
                iat = row["iat"]

                current_time += float(iat)

                # =====================
                # Direction mapping
                # =====================
                if direction == 0:
                    
                    src_mac = client_mac
                    dst_mac = "ff:ff:ff:ff:ff:ff"

                    src_ip = "0.0.0.0"
                    dst_ip = "255.255.255.255"
                    
                    sport = 68
                    dport = 67
                    op = 1  # BOOTREQUEST

                else:
                    src_mac = server_mac
                    dst_mac = client_mac

                    src_ip = server_ip
                    dst_ip = client_ip

                    sport = 67
                    dport = 68
                    op = 2  # BOOTREPLY

                # =====================
                # Build packet
                # =====================

                ether = Ether(src=src_mac, dst=dst_mac)

                ip = IP(src=src_ip, dst=dst_ip)

                udp = UDP(sport=sport, dport=dport)

                bootp = BOOTP(
                    op=op,
                    xid=xid,
                    chaddr=mac2str(client_mac)
                )

                dhcp = DHCP(options=[
                    ("message-type", int(dhcp_type)),
                    ("end")
                ])

                pkt = ether / ip / udp / bootp / dhcp
                
                current_len = len(pkt)
                if pkt_len > current_len:
                    pad_len = int(pkt_len - current_len) 
                    pkt = pkt / Raw(load=b'\x00'*pad_len)

                pkt.time = current_time

                packets.append(pkt)

        return packets