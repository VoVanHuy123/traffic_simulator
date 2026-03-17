# from scapy.all import IP, TCP,Raw
# import random


# def generate_tcp_handshake(src_ip, dst_ip, src_port, dst_port, start_time=0):

#     packets = []

#     seq_client = random.randint(1000, 50000)
#     seq_server = random.randint(1000, 50000)

#     t = start_time

#     # SYN
#     syn = IP(src=src_ip, dst=dst_ip) / TCP(
#         sport=src_port,
#         dport=dst_port,
#         flags="S",
#         seq=seq_client
#     )
#     syn.time = t
#     packets.append(syn)

#     t += 0.001

#     # SYN ACK
#     syn_ack = IP(src=dst_ip, dst=src_ip) / TCP(
#         sport=dst_port,
#         dport=src_port,
#         flags="SA",
#         seq=seq_server,
#         ack=seq_client + 1
#     )
#     syn_ack.time = t
#     packets.append(syn_ack)

#     t += 0.001

#     # ACK
#     ack = IP(src=src_ip, dst=dst_ip) / TCP(
#         sport=src_port,
#         dport=dst_port,
#         flags="A",
#         seq=seq_client + 1,
#         ack=seq_server + 1
#     )
#     ack.time = t
#     packets.append(ack)

#     return packets, seq_client + 1, seq_server + 1, t
# def generate_tcp_close(src_ip, dst_ip, src_port, dst_port,
#                        seq_client, seq_server, start_time):

#     packets = []

#     t = start_time

#     # FIN from client
#     fin1 = IP(src=src_ip, dst=dst_ip) / TCP(
#         sport=src_port,
#         dport=dst_port,
#         flags="FA",
#         seq=seq_client,
#         ack=seq_server
#     )
#     fin1.time = t
#     packets.append(fin1)

#     t += 0.001

#     # ACK from server
#     ack1 = IP(src=dst_ip, dst=src_ip) / TCP(
#         sport=dst_port,
#         dport=src_port,
#         flags="A",
#         seq=seq_server,
#         ack=seq_client + 1
#     )
#     ack1.time = t
#     packets.append(ack1)

#     t += 0.001

#     # FIN from server
#     fin2 = IP(src=dst_ip, dst=src_ip) / TCP(
#         sport=dst_port,
#         dport=src_port,
#         flags="FA",
#         seq=seq_server,
#         ack=seq_client + 1
#     )
#     fin2.time = t
#     packets.append(fin2)

#     t += 0.001

#     # ACK from client
#     ack2 = IP(src=src_ip, dst=dst_ip) / TCP(
#         sport=src_port,
#         dport=dst_port,
#         flags="A",
#         seq=seq_client + 1,
#         ack=seq_server + 1
#     )
#     ack2.time = t
#     packets.append(ack2)

#     return packets

# def generate_response_segments(dst, src, dport, sport, seq_server, seq_client, size, t, model):

#     packets = []

#     remaining = size

#     while remaining > 0:

#         seg = min(1460, remaining)

#         payload = Raw(load=random_payload(seg))

#         pkt = IP(src=dst,dst=src)/TCP(
#             sport=dport,
#             dport=sport,
#             flags="PA",
#             seq=seq_server,
#             ack=seq_client
#         )/payload

#         pkt.time = t
#         packets.append(pkt)

#         seq_server += seg
#         remaining -= seg

#         t += max(0.0005, np.random.normal(model["iat_mean"]["mean"],0.002))

#     return packets, seq_server, t