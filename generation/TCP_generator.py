

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import numpy as np
import random
from scapy.all import TCP,IP,Raw
from .base_generator import BaseFlowGenerator
from rules.protocol_rules import HTTP


class TCPFlowGenerator(BaseFlowGenerator):

    protocol = "tcp"

    def build_packets(self, all_df, base_time):

        packets = []
        client_port = np.random.randint(1024, 65535)
        server_port = 80


        # TCP STATE (QUAN TRỌNG NHẤT)

        client_seq = np.random.randint(1000, 5000)
        server_seq = np.random.randint(5000, 10000)

        client_next_seq = client_seq
        server_next_seq = server_seq

        client_ack = 0
        server_ack = 0

        time = base_time
        for df in all_df:

            # NETWORK CONFIG

            c_num = np.random.randint(1, 100)
            s_num = np.random.randint(1, 100)
            client_ip = f"192.168.1.{c_num}"
            server_ip = f"192.168.1.{s_num}"



            # LOOP PACKETS

            for row in df.to_dict("records"):
                request_sent = False
                response_sent = False
                time += float(row["iat"])

                direction = int(row["direction"])
                flags = int(row["tcp_flags"])
                pkt_len = int(row["packet_length"])


                # DETERMINE SIDE

                if direction == 0:
                    sip, dip = client_ip, server_ip
                    sport, dport = client_port, server_port

                    seq = client_next_seq
                    ack = client_ack

                    is_client = True
                else:
                    sip, dip = server_ip, client_ip
                    sport, dport = server_port, client_port

                    seq = server_next_seq
                    ack = server_ack

                    is_client = False


                # DETERMINE PAYLOAD (QUAN TRỌNG)

                payload_size = 0

                # PSH => có data
                if flags & 0x08:
                    payload_size = pkt_len

                # SYN hoặc FIN => consume 1 seq
                elif flags & 0x02 or flags & 0x01:
                    payload_size = 1
                    # payload_size = pkt_len

                # ACK only => không có data
                else:
                    payload_size = 0


                # BUILD PACKET

                tcp_layer = TCP(
                    sport=sport,
                    dport=dport,
                    flags=flags,
                    seq=seq,
                    ack=ack,
                    window=64240
                )

                pkt = IP(src=sip, dst=dip) / tcp_layer

                #  ADD PAYLOAD (FIX LEN=40)
                if payload_size > 1:
                    payload = b"A" * payload_size

                    pkt = pkt / Raw(load=payload)

                pkt.time = time
                packets.append(pkt)


                # UPDATE TCP STATE (CORE)

                if is_client:
                    client_next_seq += payload_size

                    # server sẽ ACK lại client
                    server_ack = client_next_seq

                else:
                    server_next_seq += payload_size

                    # client sẽ ACK lại server
                    client_ack = server_next_seq

        return packets



class HTTPFlowGenerator(TCPFlowGenerator):

    protocol = "http"
    
    
    def random_http_request(self):
        i = random.uniform(1,10)
        url = random.choice(HTTP["urls"])
        host = random.choice(HTTP["hosts"])

        req = f"GET {url} HTTP/1.1\r\nHost: {host}\r\n\r\n"
        return req.encode()

    def random_http_response(self):
        status = random.choice(HTTP["status_codes"])
        body = random.choice(HTTP["bodies"])

        headers = b"HTTP/1.1 " + status + b"\r\n"
        headers += f"Content-Length: {len(body)}\r\n".encode()
        headers += b"\r\n"

        return headers + body


    def build_packets(self, all_df, base_time):

        packets = []
        client_port = np.random.randint(1024, 65535)
        server_port = 80


        # TCP STATE (QUAN TRỌNG NHẤT)

        client_seq = np.random.randint(1000, 5000)
        server_seq = np.random.randint(5000, 10000)

        client_next_seq = client_seq
        server_next_seq = server_seq

        client_ack = 0
        server_ack = 0

        time = base_time
        for df in all_df:
            
            # NETWORK CONFIG
            
            c_num = np.random.randint(1, 100)
            s_num = np.random.randint(1, 100)
            client_ip = f"192.168.1.{c_num}"
            server_ip = f"192.168.1.{s_num}"


            
            # LOOP PACKETS
            
            for row in df.to_dict("records"):
                request_sent = False
                response_sent = False
                time += float(row["iat"])

                direction = int(row["direction"])
                flags = int(row["tcp_flags"])
                pkt_len = int(row["packet_length"])

                
                # DETERMINE SIDE
                
                if direction == 0:
                    sip, dip = client_ip, server_ip
                    sport, dport = client_port, server_port

                    seq = client_next_seq
                    ack = client_ack

                    is_client = True
                else:
                    sip, dip = server_ip, client_ip
                    sport, dport = server_port, client_port

                    seq = server_next_seq
                    ack = server_ack

                    is_client = False

                
                # DETERMINE PAYLOAD (QUAN TRỌNG)
                
                payload_size = 0

                # PSH => có data
                if flags & 0x08:
                    payload_size = pkt_len

                # SYN hoặc FIN => consume 1 seq
                elif flags & 0x02 or flags & 0x01:
                    payload_size = 1
                    # payload_size = pkt_len

                # ACK only => không có data
                else:
                    payload_size = 0

                
                # BUILD PACKET
                
                tcp_layer = TCP(
                    sport=sport,
                    dport=dport,
                    flags=flags,
                    seq=seq,
                    ack=ack,
                    window=64240
                )

                pkt = IP(src=sip, dst=dip) / tcp_layer

                #  ADD PAYLOAD (FIX LEN=40)
                if payload_size > 1:

                    if direction == 0:
                        base = self.random_http_request()
                    else:
                        base = self.random_http_response()

                    # resize payload cho khớp packet_length
                    if len(base) < payload_size:
                        payload = base + b"A" * (payload_size - len(base))
                    else:
                        payload = base[:payload_size]

                    pkt = pkt / Raw(load=payload)

                pkt.time = time
                packets.append(pkt)

                
                # UPDATE TCP STATE (CORE)
                
                if is_client:
                    client_next_seq += payload_size

                    # server sẽ ACK lại client
                    server_ack = client_next_seq

                else:
                    server_next_seq += payload_size

                    # client sẽ ACK lại server
                    client_ack = server_next_seq

        return packets