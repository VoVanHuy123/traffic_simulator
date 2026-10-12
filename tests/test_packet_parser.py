from scapy.all import ARP, BOOTP, DHCP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether

from preprocessing.packet_parser import PacketParser


def make_parser():
    return PacketParser()


def test_detect_protocol_http_by_port_80():
    pkt = IP() / TCP(sport=12345, dport=80)
    assert make_parser().detect_protocol(pkt) == "HTTP"


def test_detect_protocol_https_by_port_443():
    pkt = IP() / TCP(sport=12345, dport=443)
    assert make_parser().detect_protocol(pkt) == "HTTPS"


def test_detect_protocol_dns_over_tcp_by_port_53():
    pkt = IP() / TCP(sport=53, dport=12345)
    assert make_parser().detect_protocol(pkt) == "DNS"


def test_detect_protocol_generic_tcp():
    pkt = IP() / TCP(sport=5555, dport=6666)
    assert make_parser().detect_protocol(pkt) == "TCP"


def test_detect_protocol_dns_over_udp():
    pkt = IP() / UDP(sport=12345, dport=53)
    assert make_parser().detect_protocol(pkt) == "DNS"


def test_detect_protocol_dhcp_by_udp_port_68():
    pkt = IP() / UDP(sport=67, dport=68)
    assert make_parser().detect_protocol(pkt) == "DHCP"


def test_detect_protocol_generic_udp():
    pkt = IP() / UDP(sport=5000, dport=6000)
    assert make_parser().detect_protocol(pkt) == "UDP"


def test_detect_protocol_icmp():
    pkt = IP() / ICMP()
    assert make_parser().detect_protocol(pkt) == "ICMP"


def test_detect_protocol_other():
    pkt = Ether()
    assert make_parser().detect_protocol(pkt) == "OTHER"


def test_parse_tcp_fills_ip_and_port_fields():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1111, dport=80)
    data = make_parser().parse(pkt)

    assert data["src_ip"] == "10.0.0.1"
    assert data["dst_ip"] == "10.0.0.2"
    assert data["src_port"] == 1111
    assert data["dst_port"] == 80
    assert data["transport"] == "TCP"
    assert data["protocol"] == "http"


def test_parse_udp_dns_fills_dns_id():
    pkt = IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=2222, dport=53) / DNS(id=4242, qd=DNSQR(qname="example.com"))
    data = make_parser().parse(pkt)

    assert data["protocol"] == "dns"
    assert data["id"] == 4242


def test_parse_icmp_fills_icmp_id():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(id=777)
    data = make_parser().parse(pkt)

    assert data["protocol"] == "icmp"
    assert data["transport"] == "ICMP"
    assert data["icmp_id"] == 777


def test_parse_arp_fills_ip_fields_no_ports():
    pkt = ARP(psrc="192.168.1.10", pdst="192.168.1.20")
    data = make_parser().parse(pkt)

    assert data["protocol"] == "arp"
    assert data["src_ip"] == "192.168.1.10"
    assert data["dst_ip"] == "192.168.1.20"
    assert data["transport"] == "ARP"


def test_parse_dhcp_fills_xid():
    pkt = Ether() / IP() / UDP(sport=68, dport=67) / BOOTP(xid=99887766) / DHCP(options=[("message-type", 1), "end"])
    data = make_parser().parse(pkt)

    assert data["protocol"] == "dhcp"
    assert data["xid"] == 99887766


def test_parse_unknown_packet_returns_defaults():
    pkt = Ether()
    data = make_parser().parse(pkt)

    assert data["protocol"] is None
    assert data["src_ip"] is None
