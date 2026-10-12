from preprocessing import ExtractRegistry
from preprocessing.flow_builder import FlowBuilder
from preprocessing.flow_cleaner import FlowCleaner


def test_flow_builder_groups_arp_packets_into_flows(sample_pcap):
    builder = FlowBuilder(ExtractRegistry)
    flows = builder.build(sample_pcap("arp"))

    assert len(flows) > 0
    for flow in flows:
        assert flow["protocol"] == "arp"
        assert len(flow["packets"]) >= 1
        # packets within a flow should be chronologically ordered as appended
        times = [float(p.time) for p in flow["packets"]]
        assert times == sorted(times)


def test_flow_builder_groups_dhcp_packets_into_flows(sample_pcap):
    builder = FlowBuilder(ExtractRegistry)
    flows = builder.build(sample_pcap("dhcp"))

    assert len(flows) > 0
    assert all(f["protocol"] == "dhcp" for f in flows)


def test_flow_builder_groups_icmp_packets_into_flows(sample_pcap):
    # data/icmp_pcap.pcap is a real capture and also contains a handful of
    # DNS lookups alongside the ICMP traffic, so only assert on the ICMP subset.
    builder = FlowBuilder(ExtractRegistry)
    flows = builder.build(sample_pcap("icmp"))

    icmp_flows = [f for f in flows if f["protocol"] == "icmp"]
    assert len(icmp_flows) > 0


def test_flow_cleaner_drops_single_packet_flows(sample_pcap):
    builder = FlowBuilder(ExtractRegistry)
    flows = builder.build(sample_pcap("arp"))

    cleaner = FlowCleaner("arp")
    cleaned = cleaner.clean(flows)

    assert all(len(f["packets"]) >= 2 for f in cleaned)
    # cleaning must never invent flows
    assert len(cleaned) <= len(flows)


def test_flow_cleaner_dhcp_crashes_on_validate_flow_rules_mismatch(sample_pcap):
    """Reproduces a real bug: FlowCleaner.clean() calls
    handler.validate_flow(flow, self.rules) where self.rules is ALREADY
    PROTOCOL_RULES[protocol]["cleaning_rules"] (see preprocessing/flow_cleaner.py).
    Every handler except DHCPHandler treats that argument as the cleaning_rules
    dict directly (e.g. TCPHandler does rules.get("max_packets", ...)).
    DHCPHandler.validate_flow instead does rules.get("cleaning_rules").get(...),
    double-unwrapping a dict that has no nested "cleaning_rules" key, so it
    raises AttributeError on every real DHCP flow -- `traffic extract -p dhcp`
    is currently broken."""
    import pytest

    builder = FlowBuilder(ExtractRegistry)
    flows = builder.build(sample_pcap("dhcp"))

    with pytest.raises(AttributeError):
        FlowCleaner("dhcp").clean(flows)
