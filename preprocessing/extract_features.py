
from scapy.all import rdpcap, ARP, ICMP, IP, IPv6, TCP, UDP
import csv
import numpy as np
from collections import defaultdict



# -----------------------------
# Detect application protocol
# -----------------------------
def detect_protocol(pkt):

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


# -----------------------------
# Build bidirectional flows
# -----------------------------
def build_flows(input_pcap):

    packets = rdpcap(input_pcap)
    packets = sorted(packets, key=lambda x: x.time)

    flows = defaultdict(list)

    for pkt in packets:

        # -------- ARP --------
        if pkt.haslayer(ARP):

            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst

            src_port = 0
            dst_port = 0

            transport = "ARP"
            protocol = "ARP"

        # -------- IPv4 --------
        elif pkt.haslayer(IP):

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            if pkt.haslayer(TCP):

                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                transport = "TCP"

            elif pkt.haslayer(UDP):

                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                transport = "UDP"
            elif pkt.haslayer(ICMP):

                src_port = 0
                dst_port = 0
                transport = "ICMP"

            else:
                continue

            protocol = detect_protocol(pkt)

        # -------- IPv6 --------
        elif pkt.haslayer(IPv6):

            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst

            if pkt.haslayer(TCP):

                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                transport = "TCP"

            elif pkt.haslayer(UDP):

                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                transport = "UDP"

            else:
                continue

            protocol = detect_protocol(pkt)

        else:
            continue

        flow_key = tuple(sorted([
            (src_ip, src_port),
            (dst_ip, dst_port)
        ])) + (transport, protocol)

        flows[flow_key].append(pkt)

    return flows




def extract_features(flows, output_csv):

    rows = []

    for flow_key, packets in flows.items():

        packets = sorted(packets, key=lambda x: x.time)

        (ip1, port1), (ip2, port2), transport, protocol = flow_key

        src_ip = ip1
        dst_ip = ip2
        src_port = port1
        dst_port = port2

        packet_count = len(packets)
        print (f"packet_count: {packet_count}")

        sizes = [len(pkt) for pkt in packets]
        total_bytes = sum(sizes)
        avg_packet_size = float(np.mean(sizes))

        times = [float(pkt.time) for pkt in packets]

        if len(times) > 1:
            flow_duration = times[-1] - times[0]
            iat = np.diff(times)
            iat_mean = float(np.mean(iat))
        else:
            flow_duration = 0
            iat_mean = 0

        # if flow_duration <= 0:
        #     continue

        # if packet_count <= 2:
        #     continue

        # if packet_count > 100:
        #     continue

        
        flow_duration = np.log1p(flow_duration)
        packet_count = np.log1p(packet_count)
        avg_packet_size = np.log1p(avg_packet_size)
        iat_mean = np.log1p(iat_mean)

        rows.append([
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            transport,
            protocol,
            flow_duration,
            packet_count,
            total_bytes,
            avg_packet_size,
            iat_mean
        ])

    # -----------------------------
    # WRITE CSV
    # -----------------------------
    with open(output_csv, "w", newline="") as f:

        writer = csv.writer(f)

        writer.writerow([
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "transport",
            "protocol",
            "flow_duration",
            "packet_count",
            "total_bytes",
            "avg_packet_size",
            "iat_mean"
        ])

        writer.writerows(rows)

    print("Feature extraction completed")

def extract_packet_sequences(flows, output_csv):

    rows = []

    flow_id = 0

    for flow_key, packets in flows.items():

        packets = sorted(packets, key=lambda x: x.time)

        (ip1, port1), (ip2, port2), transport, protocol = flow_key

        times = [float(pkt.time) for pkt in packets]

        if len(times) <= 1:
            continue

        last_time = times[0]

        for i, pkt in enumerate(packets):

            timestamp = float(pkt.time)

            # -----------------------------
            # IAT
            # -----------------------------
            if i == 0:
                iat = 0
            else:
                iat = timestamp - last_time

            last_time = timestamp

            # -----------------------------
            # packet length
            # -----------------------------
            packet_length = len(pkt)

            # -----------------------------
            # direction
            # -----------------------------
            if IP in pkt:
                src = pkt[IP].src
            elif IPv6 in pkt:
                src = pkt[IPv6].src
            else:
                continue

            if src == ip1:
                direction = "fwd"
            else:
                direction = "bwd"

            # -----------------------------
            # TCP flags
            # -----------------------------
            if TCP in pkt:
                protocol = "TCP"
                flags = str(pkt[TCP].flags)

            elif UDP in pkt:
                protocol = "UDP"
                flags = "NONE"

            elif ICMP in pkt:
                protocol = "ICMP"
                flags = pkt[ICMP].type

            rows.append([
                flow_id,
                iat,
                packet_length,
                direction,
                flags
            ])

        flow_id += 1

    # -----------------------------
    # WRITE CSV
    # -----------------------------
    with open(output_csv, "w", newline="") as f:

        writer = csv.writer(f)

        writer.writerow([
            "flow_id",
            "iat",
            "packet_length",
            "direction",
            "tcp_flags"
        ])

        writer.writerows(rows)

    print("Packet sequence extraction completed")
# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    protocol = "dhcp"

    input_pcap = f"data/{protocol}_pcap.pcap"

    flows = build_flows(input_pcap)

    extract_features(
        flows,
        f"dataset/{protocol}_flow_dataset.csv"
    )
    extract_packet_sequences(
        flows,
        f"dataset/{protocol}_sequences_dataset.csv"
    )
  
