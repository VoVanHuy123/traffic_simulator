from scapy.all import IP

from generation.base_generator import BaseFlowGenerator


class DummyGenerator(BaseFlowGenerator):
    protocol = "dummy"

    def build_packets(self, all_df, base_time):
        pkt = IP()
        pkt.time = base_time
        return [pkt]


def test_match_compares_protocol_name():
    gen = DummyGenerator()
    assert gen.match("dummy") is True
    assert gen.match("other") is False


def test_base_build_packets_is_abstract():
    import pytest

    gen = BaseFlowGenerator()
    with pytest.raises(NotImplementedError):
        gen.build_packets([], 0.0)


def test_to_pcap_calls_build_packets_and_writes_readable_file(tmp_path, monkeypatch):
    from scapy.all import rdpcap

    monkeypatch.chdir(tmp_path)
    gen = DummyGenerator()

    gen.to_pcap([], "out.pcap")

    packets = rdpcap(str(tmp_path / "out.pcap"))
    assert len(packets) == 1
