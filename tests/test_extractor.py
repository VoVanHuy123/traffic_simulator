import csv

from preprocessing import ExtractRegistry
from preprocessing.flow_builder import FlowBuilder
from preprocessing.flow_cleaner import FlowCleaner
from preprocessing.extractor import Extractor
from rules.protocol_rules import PROTOCOL_RULES


def _build_clean_flows(sample_pcap, protocol):
    flows = FlowBuilder(ExtractRegistry).build(sample_pcap(protocol))
    return FlowCleaner(protocol).clean(flows)


def test_extract_flow_features_writes_expected_header_and_rows(sample_pcap, tmp_path):
    flows = _build_clean_flows(sample_pcap, "icmp")
    out_csv = tmp_path / "icmp_flow_dataset.csv"

    Extractor("icmp").extract_flow_features(flows, str(out_csv))

    with open(out_csv, newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        rows = list(reader)

    assert header == ["flow_id"] + list(PROTOCOL_RULES["icmp"]["csv_feature_fields"])
    assert len(rows) == len(flows)
    # packet_count column must be a positive integer for every extracted flow
    packet_count_idx = header.index("packet_count")
    assert all(int(row[packet_count_idx]) >= 1 for row in rows)


def test_extract_sequences_features_writes_one_row_per_packet(sample_pcap, tmp_path):
    flows = _build_clean_flows(sample_pcap, "icmp")
    out_csv = tmp_path / "icmp_sequences_dataset.csv"

    Extractor("icmp").extract_sequences_features(flows, str(out_csv))

    with open(out_csv, newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        rows = list(reader)

    assert header == ["flow_id"] + list(PROTOCOL_RULES["icmp"]["csv_sequence_fields"])
    total_packets = sum(len(f["packets"]) for f in flows)
    assert len(rows) == total_packets


def test_extract_sequences_features_arp_crashes_on_direction_bug(sample_pcap, tmp_path):
    """Reproduces the ARPHandler.extract_direction bug (missing `self`) through
    the real extraction path used by `traffic extract -p arp`."""
    import pytest

    flows = _build_clean_flows(sample_pcap, "arp")
    out_csv = tmp_path / "arp_sequences_dataset.csv"

    with pytest.raises(TypeError):
        Extractor("arp").extract_sequences_features(flows, str(out_csv))


def test_extract_sequences_by_stages_splits_http_into_stage_files(sample_pcap, tmp_path, isolated_cwd):
    flows = _build_clean_flows(sample_pcap, "http")
    (isolated_cwd / "dataset" / "http").mkdir(parents=True)

    Extractor("http").extract_sequences_by_stages(flows, "dataset/http/http_sequences_dataset.csv")

    for stage in PROTOCOL_RULES["http"]["stages"]:
        stage_file = isolated_cwd / "dataset" / "http" / f"http_{stage}_sequences_dataset.csv"
        assert stage_file.exists()
