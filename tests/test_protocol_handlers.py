import pytest
from scapy.all import ARP, BOOTP, DHCP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether

from preprocessing.protocols.arp import ARPHandler
from preprocessing.protocols.dhcp import DHCPHandler
from preprocessing.protocols.dns import DNSHandler
from preprocessing.protocols.imcp import ICMPHandler
from preprocessing.protocols.isup import ISUPHandler
from preprocessing.protocols.tcp import HTTPHandler, TCPHandler
from preprocessing.packet_parser import PacketParser


# ---------------------------------------------------------------------------
# match()
# ---------------------------------------------------------------------------

def test_arp_handler_matches_arp_only():
    handler = ARPHandler()
    assert handler.match(ARP()) is True
    assert not handler.match(IP() / TCP())


def test_dhcp_handler_matches_dhcp_layer():
    handler = DHCPHandler()
    pkt = Ether() / IP() / UDP(sport=68, dport=67) / BOOTP() / DHCP(options=[("message-type", 1), "end"])
    assert handler.match(pkt) is True
    assert not handler.match(IP() / TCP())


def test_dns_handler_matches_dns_layer():
    handler = DNSHandler()
    pkt = IP() / UDP(dport=53) / DNS(qd=DNSQR(qname="a.com"))
    assert handler.match(pkt) is True
    assert not handler.match(IP() / TCP())


def test_icmp_handler_matches_icmp():
    handler = ICMPHandler()
    assert handler.match(IP() / ICMP()) is True
    assert not handler.match(IP() / UDP())


def test_tcp_handler_matches_any_tcp_including_http_port():
    handler = TCPHandler()
    assert handler.match(IP() / TCP(dport=80)) is True
    assert handler.match(IP() / TCP(dport=9999)) is True
    assert not handler.match(IP() / UDP())


def test_http_handler_matches_only_port_80():
    handler = HTTPHandler()
    assert handler.match(IP() / TCP(sport=1234, dport=80)) is True
    assert handler.match(IP() / TCP(sport=80, dport=1234)) is True
    assert not handler.match(IP() / TCP(sport=1234, dport=9999))


def test_registry_dispatches_http_before_generic_tcp():
    """HTTPHandler must be registered ahead of TCPHandler in ExtractRegistry,
    otherwise every port-80 packet would be swallowed by the generic TCP
    handler and never treated as HTTP."""
    from preprocessing import ExtractRegistry

    http_pkt = IP() / TCP(sport=1234, dport=80)
    handler = ExtractRegistry.get_handler(http_pkt)
    assert handler.name == "http"

    plain_tcp_pkt = IP() / TCP(sport=1234, dport=9999)
    handler = ExtractRegistry.get_handler(plain_tcp_pkt)
    assert handler.name == "tcp"


# ---------------------------------------------------------------------------
# build_flow_key()
# ---------------------------------------------------------------------------

def test_arp_flow_key_is_order_independent_ip_pair():
    handler = ARPHandler()
    key1 = handler.build_flow_key({"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"})
    key2 = handler.build_flow_key({"src_ip": "10.0.0.2", "dst_ip": "10.0.0.1"})
    assert key1 == key2


def test_dhcp_flow_key_uses_xid():
    handler = DHCPHandler()
    assert handler.build_flow_key({"xid": 555}) == ("dhcp", 555)


def test_icmp_flow_key_uses_sorted_ip_pair_and_icmp_id():
    handler = ICMPHandler()
    data = {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "icmp_id": 42}
    key = handler.build_flow_key(data)
    assert key == ("icmp", ("10.0.0.1", "10.0.0.5"), 42)


# ---------------------------------------------------------------------------
# is_session_start()
# ---------------------------------------------------------------------------

def test_arp_session_starts_on_request_opcode():
    handler = ARPHandler()
    assert handler.is_session_start(ARP(op=1)) is True
    assert handler.is_session_start(ARP(op=2)) is False


def test_dns_session_starts_on_query():
    handler = DNSHandler()
    query = DNS(qr=0, qd=DNSQR(qname="a.com"))
    response = DNS(qr=1, qd=DNSQR(qname="a.com"))
    assert handler.is_session_start(query) is True
    assert handler.is_session_start(response) is False


def test_icmp_session_starts_on_echo_request():
    handler = ICMPHandler()
    assert handler.is_session_start(IP() / ICMP(type=8)) is True
    assert handler.is_session_start(IP() / ICMP(type=0)) is False


def test_tcp_session_starts_on_syn_without_ack():
    handler = TCPHandler()
    syn = IP() / TCP(flags="S")
    synack = IP() / TCP(flags="SA")
    assert handler.is_session_start(syn) is True
    assert handler.is_session_start(synack) is False


# ---------------------------------------------------------------------------
# extract_flags()
# ---------------------------------------------------------------------------

def test_dns_extract_flags_reports_qr_bit():
    handler = DNSHandler()
    assert handler.extract_flags(DNS(qr=0, qd=DNSQR(qname="a.com")))["dns_type"] == 0
    assert handler.extract_flags(DNS(qr=1, qd=DNSQR(qname="a.com")))["dns_type"] == 1


def test_arp_extract_flags_reports_opcode():
    handler = ARPHandler()
    assert handler.extract_flags(ARP(op=1)) == {"arp_opcode": 1}


def test_tcp_extract_flags_reports_flag_bits():
    handler = TCPHandler()
    pkt = IP() / TCP(flags="SA")
    assert handler.extract_flags(pkt) == {"tcp_flags": int(pkt[TCP].flags)}


def test_isup_msg_name_lookup_from_numeric_code():
    handler = ISUPHandler()
    assert handler.get_stage_name(1) == "setup"   # IAM
    assert handler.get_stage_name(3) == "active"  # ANM
    assert handler.get_stage_name(5) == "cleanup"  # REL
    assert handler.get_stage_name(999) is None


# ---------------------------------------------------------------------------
# extract_direction() -- known bug: ARPHandler/DHCPHandler define this method
# without `self`, so calling it as a bound method (handler.extract_direction(pkt, data))
# raises TypeError. This is how preprocessing/extractor.py actually calls it.
# ---------------------------------------------------------------------------

def test_arp_extract_direction_bound_call_raises_typeerror():
    """Documents a real bug: ARPHandler.extract_direction(pkt, data=None) is
    missing `self`, so preprocessing/extractor.py's bound call
    `handler.extract_direction(pkt, key_dict)` crashes with a TypeError."""
    handler = ARPHandler()
    pkt = ARP(psrc="10.0.0.1", pdst="10.0.0.2")
    data = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}

    with pytest.raises(TypeError):
        handler.extract_direction(pkt, data)


def test_dhcp_extract_direction_bound_call_raises_typeerror():
    """Same bug as ARPHandler, see test_arp_extract_direction_bound_call_raises_typeerror."""
    handler = DHCPHandler()
    pkt = Ether() / IP() / UDP(sport=68, dport=67) / BOOTP()

    with pytest.raises(TypeError):
        handler.extract_direction(pkt, {})


def test_dns_extract_direction_uses_base_implementation():
    """DNSHandler has no override, so it should use ProtocolHandler.extract_direction
    (which does take self correctly) and compare packet src IP to the flow's
    recorded src_ip."""
    handler = DNSHandler()
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP() / DNS(qd=DNSQR(qname="a.com"))
    data = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}

    assert handler.extract_direction(pkt, data) == {"direction": 0}

    reply_pkt = IP(src="10.0.0.2", dst="10.0.0.1") / UDP() / DNS(qd=DNSQR(qname="a.com"))
    assert handler.extract_direction(reply_pkt, data) == {"direction": 1}


def test_isup_extract_direction_defaults_to_zero_without_src_ip():
    handler = ISUPHandler()
    assert handler.extract_direction(None, {}) == {"direction": 0}
