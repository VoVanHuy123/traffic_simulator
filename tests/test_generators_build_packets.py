import pandas as pd
import pytest
from scapy.all import ARP, BOOTP, DHCP, DNS, ICMP, IP, SCTP, TCP, UDP, Ether

from generation.ARP_generator import ARPFlowGenerator
from generation.ICMP_generator import ICMPFlowGenerator
from generation.UDP_generator import DHCPFlowGenerator, DNSFlowGenerator
from generation.TCP_generator import HTTPFlowGenerator, TCPFlowGenerator
from generation.ISUP_generator import ISUPFlowGenerator
from generation.Diameter_generator import DiameterFlowGenerator
from generation.MAP_generator import MAPFlowGenerator

BASE_TIME = 1_750_000_000.0


def test_arp_build_packets_returns_ether_arp_frames():
    gen = ARPFlowGenerator()
    df = pd.DataFrame([
        {"direction": 0, "arp_opcode": 1, "packet_length": 60, "iat": 0.01},
        {"direction": 1, "arp_opcode": 2, "packet_length": 60, "iat": 0.02},
    ])

    packets = gen.build_packets([df], BASE_TIME)

    assert len(packets) == 2
    for pkt in packets:
        assert pkt.haslayer(Ether)
        assert pkt.haslayer(ARP)
        assert pkt.time >= BASE_TIME
    times = [float(p.time) for p in packets]
    assert times == sorted(times)


def test_icmp_build_packets_returns_ip_icmp_packets_with_alternating_direction():
    gen = ICMPFlowGenerator()
    df = pd.DataFrame([
        {"direction": 0, "icmp_type": 8, "packet_length": 60, "iat": 0.001},
        {"direction": 1, "icmp_type": 0, "packet_length": 60, "iat": 0.001},
    ])

    packets = gen.build_packets([df], BASE_TIME)

    assert len(packets) == 2
    assert all(p.haslayer(IP) and p.haslayer(ICMP) for p in packets)
    assert packets[0][ICMP].type == 8
    assert packets[1][ICMP].type == 0


def test_dns_build_packets_alternates_query_and_response():
    gen = DNSFlowGenerator()
    df = pd.DataFrame([
        {"direction": 0, "dns_type": 1, "packet_length": 60, "iat": 0.001},
        {"direction": 1, "dns_type": 1, "packet_length": 80, "iat": 0.001},
    ])

    packets = gen.build_packets([df], BASE_TIME)

    assert len(packets) == 2
    assert packets[0].haslayer(DNS) and packets[0][DNS].qr == 0
    assert packets[1].haslayer(DNS) and packets[1][DNS].qr == 1


def test_dhcp_build_packets_uses_bootp_broadcast_for_client_direction():
    gen = DHCPFlowGenerator()
    df = pd.DataFrame([
        {"direction": 0, "dhcp_msg_type": 1, "packet_length": 300, "iat": 0.001},
        {"direction": 1, "dhcp_msg_type": 2, "packet_length": 300, "iat": 0.001},
    ])

    packets = gen.build_packets([df], BASE_TIME)

    assert len(packets) == 2
    assert all(p.haslayer(BOOTP) and p.haslayer(DHCP) for p in packets)
    assert packets[0][IP].dst == "255.255.255.255"
    assert packets[1][IP].src == "192.168.1.1"


def test_tcp_build_packets_produces_ip_tcp_with_requested_flags():
    gen = TCPFlowGenerator()
    df = pd.DataFrame([
        {"direction": 0, "tcp_flags": 2, "packet_length": 60, "iat": 0.001},   # SYN
        {"direction": 1, "tcp_flags": 18, "packet_length": 60, "iat": 0.001},  # SYN-ACK
        {"direction": 0, "tcp_flags": 16, "packet_length": 60, "iat": 0.001},  # ACK
    ])

    packets = gen.build_packets([df], BASE_TIME)

    assert len(packets) == 3
    assert all(p.haslayer(TCP) for p in packets)
    assert [int(p[TCP].flags) for p in packets] == [2, 18, 16]


def test_http_build_packets_embeds_http_payload_on_psh_packets():
    gen = HTTPFlowGenerator()
    df = pd.DataFrame([
        {"direction": 0, "tcp_flags": 2, "packet_length": 60, "iat": 0.001},
        {"direction": 0, "tcp_flags": 24, "packet_length": 80, "iat": 0.001},  # PSH+ACK, has payload
    ])

    packets = gen.build_packets([df], BASE_TIME)

    assert len(packets) == 2
    assert packets[1].haslayer("Raw")


def test_isup_build_packets_returns_sctp_frames_sorted_by_time():
    gen = ISUPFlowGenerator()
    df = pd.DataFrame([
        {"direction": 0, "isup_msg_type": "IAM", "packet_length": 20, "iat": 0.01},
        {"direction": 1, "isup_msg_type": "ACM", "packet_length": 20, "iat": 0.01},
        {"direction": 1, "isup_msg_type": "ANM", "packet_length": 20, "iat": 0.01},
    ])

    packets = gen.build_packets([df], BASE_TIME)

    assert len(packets) == 3
    assert all(p.haslayer(IP) and p.haslayer(SCTP) for p in packets)
    times = [float(p.time) for p in packets]
    assert times == sorted(times)


def test_diameter_build_packets_length_field_matches_actual_bytes_sent():
    """Regression test: the Diameter header's message-length field must equal
    the real byte count of the SCTP payload, or Wireshark/tshark flag the
    packet as [Malformed Packet] even though the header fields parse fine."""
    gen = DiameterFlowGenerator()
    df = pd.DataFrame([
        {"direction": 0, "diameter_cmd": "ULR", "packet_length": 62, "iat": 0.001},
        {"direction": 1, "diameter_cmd": "ULA", "packet_length": 48, "iat": 0.001},
    ])

    packets = gen.build_packets([df], BASE_TIME)

    for pkt in packets:
        data = bytes(pkt["SCTPChunkData"].data)
        declared_length = int.from_bytes(data[1:4], "big")
        assert declared_length == len(data)


def test_diameter_build_packets_avp_is_well_formed():
    """Regression test: the bytes after the 20-byte header must be a valid
    AVP (code/flags/length header + data, padded to a 4-byte boundary), not
    raw padding -- raw zero-byte padding still parses as a bogus AVP and
    trips [Malformed Packet] even when the outer message-length is correct."""
    gen = DiameterFlowGenerator()
    df = pd.DataFrame([
        {"direction": 0, "diameter_cmd": "ULR", "packet_length": 93, "iat": 0.001},
    ])

    packets = gen.build_packets([df], BASE_TIME)
    data = bytes(packets[0]["SCTPChunkData"].data)
    avp_bytes = data[20:]

    avp_code = int.from_bytes(avp_bytes[0:4], "big")
    avp_length = int.from_bytes(avp_bytes[5:8], "big")
    pad_len = (4 - (avp_length % 4)) % 4

    assert avp_code == 264  # Origin-Host
    assert avp_length + pad_len == len(avp_bytes)


def test_map_build_packets_returns_sctp_frames_in_declared_order():
    gen = MAPFlowGenerator()
    df = pd.DataFrame([
        {"direction": 0, "map_msg_type": "UPDATE_LOCATION", "packet_length": 100, "iat": 0.01},
        {"direction": 1, "map_msg_type": "INSERT_SUBSCRIBER_DATA", "packet_length": 120, "iat": 0.05},
        {"direction": 0, "map_msg_type": "INSERT_SUBSCRIBER_DATA_ACK", "packet_length": 70, "iat": 0.05},
        {"direction": 1, "map_msg_type": "UPDATE_LOCATION_ACK", "packet_length": 70, "iat": 0.05},
    ])

    packets = gen.build_packets([df], BASE_TIME)

    assert len(packets) == 4
    assert all(p.haslayer(IP) and p.haslayer(SCTP) for p in packets)
    times = [float(p.time) for p in packets]
    assert times == sorted(times)


def test_build_packets_base_time_shifts_the_whole_flow():
    """Two runs with different base_time should produce non-overlapping
    timelines -- this is what lets ScenarioRunner interleave protocols."""
    gen = ICMPFlowGenerator()
    df = pd.DataFrame([{"direction": 0, "icmp_type": 8, "packet_length": 60, "iat": 0.001}])

    early = gen.build_packets([df], BASE_TIME)
    later = gen.build_packets([df], BASE_TIME + 1000)

    assert float(later[0].time) > float(early[0].time)
