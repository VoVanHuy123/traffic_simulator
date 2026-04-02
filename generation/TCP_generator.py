

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import numpy as np
import pandas as pd
import random
from scapy.all import wrpcap,TCP,IP,Raw
import joblib
from .base_generator import BaseFlowGenerator
from rules.protocol_rules import PROTOCOL_RULES,HTTP
from preprocessing.data_clean import filter_valid_ack


class TCPFlowGenerator(BaseFlowGenerator):

    protocol = "tcp"
    stages = PROTOCOL_RULES[protocol].get("stages")
    


    # def decode_packet(self, parts):

    #     direction = int(parts[0])
    #     flag = int(parts[1])

    #     # packet_length bin → value
    #     length_bin = int(parts[2])
    #     length_map = {
    #         0: np.random.randint(40, 70),
    #         1: np.random.randint(70, 100),
    #         2: np.random.randint(100, 300),
    #         3: np.random.randint(300, 1500)
    #     }

    #     # iat bin → value
    #     iat_bin = int(parts[3])
    #     iat_map = {
    #         0: np.random.uniform(0.000001, 0.0001),
    #         1: np.random.uniform(0.0001, 0.01),
    #         2: np.random.uniform(0.01, 0.1),
    #         3: np.random.uniform(0.1, 1)
    #     }

    #     return {
    #         "direction": direction,
    #         "tcp_flags": flag,
    #         "packet_length": length_map[length_bin],
    #         "iat": iat_map[iat_bin]
    #     }
    def generate_sequences_by_stages(self, pkt_count):

        rules = PROTOCOL_RULES.get(self.protocol)
        stages = rules.get("stages")
        stage_pkts = rules.get("stage_packets")

        results = []
        results_dict = {
            "handshake": [],
            "data": [],
            "closing": []
        }
        remaining = pkt_count

        
        # 1. HANDSHAKE (always)
        
        handshake_count = stage_pkts.get("handshake", 0)
        results_dict["handshake"]= []

        if remaining >= handshake_count:
            self.set_model("handshake")
            df = self.generate(handshake_count)
            results.append(df)
            results_dict["handshake"] = df
            remaining -= handshake_count
        else:
            
            self.set_model("handshake")
            df = self.generate(remaining)
            results.append(df)
            return pd.concat(results, ignore_index=True)

        
        # 2. DATA
        
        has_data = False
        closing_count = stage_pkts.get("closing", 0)
        

       
        if remaining > 0:

            
            if remaining > closing_count:
                data_count = remaining - closing_count
            else:
                data_count = remaining

            if data_count > 0:
                self.set_model("data")
                df = self.generate(data_count)
                results.append(df)
                results_dict["data"]=df
                remaining -= data_count
                has_data = True

        
        # 3. CLOSING
        
        if has_data and remaining > 0:
            self.set_model("closing")
            df = self.generate(remaining)
            results.append(df)
            results_dict["closing"] = df

        
        return pd.concat(results, ignore_index=True), results_dict
    
    def fsm_handshake_pkts(self,fixed,pkts_dict):
        # 1. HANDSHAKE
        
        handshake = [
            {"direction": 0, "tcp_flags": 2},
            {"direction": 1, "tcp_flags": 18},
            {"direction": 0, "tcp_flags": 16},
        ]
        pkts = []
        if pkts_dict["handshake"] is not None:
            pkts = pkts_dict["handshake"].to_dict("records")
        else:
            pkts = pkts_dict.to_dict("records")

        for i in range(min(3, len(pkts))):
            pkt = pkts[i]
            pkt["direction"] = handshake[i]["direction"]
            pkt["tcp_flags"] = handshake[i]["tcp_flags"]
            fixed.append(pkt)
    
    def mov_first_ack_to_bottom(self, df):
        if df is None or df.empty:
            return df
        packets = df.to_dict("records")
        # If the first packet is ACK (16) → move to the end
        if packets[0]["tcp_flags"] == 16:
            first = packets.pop(0)
            packets.append(first)

        return pd.DataFrame(packets)
    
    def interleave_df_by_packet_length(self,df_list):
    
        # Sort by average packet length
        df_list = sorted(df_list, key=lambda df: df["packet_length"])

        n = len(df_list)
        mid = n // 2

        left = df_list[:mid]
        right = df_list[mid:]

        result = []

        # ---- Left processing ----
        i = 0
        while i < len(left):
            result.append(left[i])

            if i + 2 < len(left):
                result.append(left[i + 2])

            if i + 1 < len(left):
                result.append(left[i + 1])

            i += 3

        # ---- right processing----
        temp = []
        i = 0
        while i < len(right):
            if i + 1 < len(right):
                temp.append(right[i + 1])

            temp.append(right[i])

            if i + 2 < len(right):
                temp.append(right[i + 2])

            i += 3

        result.extend(temp)

        return result
    def arrange_24_16_alternately(self,pkts):
        fixed= []
        data_24 = [pkt for pkt in pkts if pkt["tcp_flags"] == 24]
        data_24 = self.interleave_df_by_packet_length(data_24)
        data_16 = [pkt for pkt in pkts if pkt["tcp_flags"] == 16]

        i, j = 0, 0
        turn_24 = True   # bắt đầu bằng 24

        while i < len(data_24) or j < len(data_16):
            
            # ƯU TIÊN 24           
            if turn_24 and i < len(data_24):
                pkt = data_24[i]
                pkt["direction"] = 0 if i % 2 == 0 else 1   # optional
                fixed.append(pkt)
                i += 1
                # nếu còn 16 thì chuyển lượt
                if j < len(data_16):
                    turn_24 = False        
            # LẤY 16    
            elif not turn_24 and j < len(data_16):
                pkt = data_16[j]
                pkt["direction"] = 1 if j % 2 == 0 else 0   # optional
                fixed.append(pkt)
                j += 1
                turn_24 = True           
            # HẾT 16 → spam 24
            elif i < len(data_24):
                pkt = data_24[i]
                pkt["direction"] = 0
                fixed.append(pkt)
                i += 1
              # HẾT 24 → lấy 16           
            elif j < len(data_16):
                pkt = data_16[j]
                pkt["direction"] = 1
                fixed.append(pkt)
                j += 1
        return fixed
    def remove_duplicate_ack(self, df):
        filtered = []
        
        prev_flags = None
        prev_direction = None

        for row in df:
            flags = row["tcp_flags"]
            direction = row["direction"]

            
            # Nếu là ACK
            if flags == 16:
                # duplicate ACK cùng direction
                if prev_flags == 16 and prev_direction == direction:
                    continue

                # ACK không có data trước đó
                if prev_flags != 24:
                    continue

            # giữ packet
            filtered.append(row)

            prev_flags = flags
            prev_direction = direction

        return filtered
    
    def re_direction_0_1_in_turn(self,fixed,pkts):
        i = 0
        while i < len(pkts):
                req = pkts[i]
                req = pkts[i]
                req["direction"] = 0
                fixed.append(req)
                i += 1

                if i >= len(pkts):
                    break

                # SERVER RESPONSE
                res = pkts[i]
                res["direction"] = 1
                fixed.append(res)
                i += 1

                if i >= len(pkts):
                    break
    
    def fix_direction_24_alternate(self,fixed,pkts):
        toggle = 0  # bắt đầu từ client (request)
        if pkts[0]["tcp_flags"] == 24:
            pkts[0]["direction"] == 0
        for pkt in pkts:
            if pkt["tcp_flags"] == 24:
                pkt["direction"] = 1
                
                # pkt["direction"] = toggle
                # toggle = 1 - toggle

            if pkt["tcp_flags"] == 16:
                pkt["direction"] = 1
                # pkt["direction"] = toggle
            fixed.append(pkt)
    def fix_direction_24(self,fixed,pkts):
        if not pkts:
            return

        found_first_24 = False
        fixed = []
        if len(pkts) >= 2:
            if pkts[0]["tcp_flags"] == 24:
                pkts[0]["direction"] = 0
            if pkts[1]["tcp_flags"] == 16:
                pkts[1]["direction"] = 1

        for pkt in pkts[2:]:
            if pkt["tcp_flags"] == 24:
                    pkt["direction"] = 1  
            elif pkt["tcp_flags"] == 16:
                pkt["direction"] = 0

            fixed.append(pkt)


    def apply_fsm(self, results_dict):

        fixed = []

        
        # 1. HANDSHAKE
        self.fsm_handshake_pkts(fixed,results_dict) 
       
        # 2. DATA (FIX ORDER + FSM)
        
        data_df = results_dict["data"]
        data_df = self.mov_first_ack_to_bottom(data_df)
        if data_df is not None:
            pkts = data_df.to_dict("records")
            pkts = self.arrange_24_16_alternately(pkts)
            pkts = self.remove_duplicate_ack(pkts)
            self.re_direction_0_1_in_turn(fixed,pkts)
            self.fix_direction_24(fixed,pkts)


        # 3. CLOSING
        if results_dict["closing"] is not None:

            closing =  results_dict["closing"]
            if isinstance(closing, pd.DataFrame):
                closing = closing.to_dict("records")

            for d in closing:
                fixed.append(d)
            # fixed.append({
            #     "direction": 0,
            #     "tcp_flags": 17,
            #     "packet_length": np.random.randint(40, 80),
            #     "iat": np.random.uniform(0.00001, 0.01)
            # })

            # fixed.append({
            #     "direction": 1,
            #     "tcp_flags": 16,
            #     "packet_length": np.random.randint(40, 80),
            #     "iat": np.random.uniform(0.00001, 0.01)
            # })

        return pd.DataFrame(fixed)

    
    def generate_sequences(self, pkt_count=10):
        df,dict = self.generate_sequences_by_stages(pkt_count)
        df = self.apply_fsm(dict)
        return df
    
    def to_pcap(self, all_df, filename="output.pcap"):

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

        time = 0
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

        # SAVE PCAP
        wrpcap(filename, packets)
        print(f" Saved {filename}")
        
    

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


    def to_pcap(self, all_df, filename="output.pcap"):

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

        time = 0
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

        # SAVE PCAP
        wrpcap(filename, packets)
        print(f" Saved {filename}")