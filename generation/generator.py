import json
import random
import numpy as np
from scapy.all import rdpcap,wrpcap,Ether, IP, TCP, UDP, ICMP, PcapReader, PcapWriter, Raw
from TCP_generator import generate_tcp_handshake,generate_tcp_close

# ---------------------------
# Load protocol model
# ---------------------------

def load_models(model_file):
    with open(model_file) as f:
        return json.load(f)


# ---------------------------
# Sample value from distribution
# ---------------------------

def sample(stat):

    mean = stat["mean"]
    std = stat["std"]

    if std == 0:
        return mean

    value = np.random.normal(mean, std)

    value = max(stat["min"], value)
    value = min(stat["max"], value)

    return value

def random_payload(size):
    return bytes(random.getrandbits(8) for _ in range(int(size)))
def sample_int(stat):
    return int(sample(stat))
# ---------------------------
# Generate random IP
# ---------------------------

def random_ip():

    return f"192.168.{random.randint(0,10)}.{random.randint(2,200)}"


# ---------------------------
# Generate one TCP conversation
# ---------------------------

def generate_tcp_flow(model, protocol="HTTP"):

    packets = []

    src = random_ip()
    dst = f"10.0.0.{random.randint(2,200)}"

    sport = random.randint(40000,60000)

    dport = random.choices(
        list(model["ports"].keys()),
        weights=model["ports"].values()
    )[0]

    dport = int(dport)

    seq_client = random.randint(1000,50000)
    seq_server = random.randint(1000,50000)

    t = 0

    # TCP handshake
    handshake, seq_client, seq_server, t = generate_tcp_handshake(
        src, dst, sport, dport, t
    )

    packets.extend(handshake)

    # -----------------------
    # Flow parameters
    # -----------------------

    packet_count = max(3, sample_int(model["packet_count"]))
    avg_size = sample_int(model["avg_packet_size"])
    iat = model["iat_mean"]["mean"]

    direction_ratio = model["direction_ratio"]

    # -----------------------
    # Generate packets
    # -----------------------

    for i in range(packet_count):

        t += max(0.0001, np.random.normal(iat, model["iat_std"]["mean"]))

        size = max(20, int(np.random.normal(avg_size, model["std_packet_size"]["mean"])))

        payload = Raw(load=random_payload(size))

        # direction decision
        if random.random() < direction_ratio:

            pkt = IP(src=src,dst=dst)/TCP(
                sport=sport,
                dport=dport,
                flags="PA",
                seq=seq_client,
                ack=seq_server
            )/payload

            pkt.time = t
            packets.append(pkt)

            seq_client += size

        else:

            pkt = IP(src=dst,dst=src)/TCP(
                sport=dport,
                dport=sport,
                flags="PA",
                seq=seq_server,
                ack=seq_client
            )/payload

            pkt.time = t
            packets.append(pkt)

            seq_server += size

    # -----------------------
    # ACK sync
    # -----------------------

    t += 0.001

    ack = IP(src=src,dst=dst)/TCP(
        sport=sport,
        dport=dport,
        flags="A",
        seq=seq_client,
        ack=seq_server
    )

    ack.time = t
    packets.append(ack)

    # -----------------------
    # TCP close
    # -----------------------

    close_packets = generate_tcp_close(
        src, dst, sport, dport, seq_client, seq_server, t+1
    )

    packets.extend(close_packets)

    return packets


# ---------------------------
# Generate many flows
# ---------------------------

def generate_traffic(model_file, protocol, flows, output):

    models = load_models(model_file)

    all_packets = []

    current_time = 0

    for i in range(flows):

        flow_packets = generate_tcp_flow(models[protocol], protocol)

        # shift time
        for p in flow_packets:
            p.time += current_time

        all_packets.extend(flow_packets)

        current_time += random.uniform(0.5,2)

    wrpcap(output, all_packets)

    print("PCAP generated:", output)



if __name__ == "__main__":
    generate_traffic(
    "models/protocol_models.json",
    "HTTP",
    20,
    "generated_http_realistic.pcap"
)