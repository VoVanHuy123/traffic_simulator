import pytest
from scapy.all import rdpcap

from generation import GenRegistry
from generation.generator import Generator
from rules.protocol_rules import PROTOCOL_RULES

# All declared protocols have both a protocols/<name>.yaml spec and a
# registered Scapy packet builder. "https" is declared in PROTOCOL_RULES but
# has no generator/spec (see test_https_protocol_has_no_generator_or_spec).
ALL_PROTOCOLS = ["arp", "icmp", "dns", "dhcp", "isup", "tcp", "http", "sip", "radius", "gtp", "rtp", "map", "diameter"]


def test_https_protocol_has_no_generator_or_spec():
    """https is declared in PROTOCOL_RULES (rules/protocol_rules.py) but there
    is no protocols/https.yaml spec and no registered generator, so
    Generator("https", ...) fails at construction."""
    with pytest.raises(Exception):
        Generator("https", GenRegistry)


@pytest.mark.parametrize("protocol", ALL_PROTOCOLS)
def test_generate_flows_needs_no_models_or_dataset_directory(protocol, isolated_cwd_no_models):
    """The whole point of the declarative spec system: generation must not
    read models/ or dataset/ at all -- isolated_cwd_no_models chdir's into a
    scratch dir that has neither, only the repo's protocols/ specs."""
    generator = Generator(protocol, GenRegistry)
    flows = generator.generate_flows(3)

    assert len(flows) == 3
    for df in flows:
        assert len(df) >= 1
        assert "direction" in df.columns
        assert "iat" in df.columns
        assert "packet_length" in df.columns
        assert set(df["direction"]) <= {0, 1}


@pytest.mark.parametrize("protocol", ALL_PROTOCOLS)
def test_export_pcap_writes_a_readable_pcap_file(protocol, isolated_cwd_no_models):
    generator = Generator(protocol, GenRegistry)
    flows = generator.generate_flows(2)

    out_path = "output/test_export.pcap"
    generator.export_pcap(flows, out_path)

    packets = rdpcap(out_path)
    assert len(packets) > 0


def test_generate_flows_returns_independent_flow_per_call(isolated_cwd_no_models):
    generator = Generator("icmp", GenRegistry)
    flows = generator.generate_flows(5)
    assert len(flows) == 5
    # each flow is independently sampled -- not all identical
    lengths = {len(df) for df in flows}
    assert isinstance(lengths, set)


def test_generate_flows_count_matches_requested_num_flows(isolated_cwd_no_models):
    generator = Generator("arp", GenRegistry)
    assert len(generator.generate_flows(0)) == 0
    assert len(generator.generate_flows(7)) == 7
