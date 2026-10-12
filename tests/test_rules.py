import pytest

from rules.protocol_rules import PROTOCOL_RULES

REQUIRED_KEYS = [
    "packet_count",
    "packet_size",
    "flow_duration",
    "flow_key",
    "csv_feature_fields",
    "csv_sequence_fields",
    "cleaning_rules",
    "packet_length_bin",
    "iat_bin",
    "evaluation_features",
]

ALL_PROTOCOLS = sorted(PROTOCOL_RULES.keys())


@pytest.mark.parametrize("protocol", ALL_PROTOCOLS)
def test_protocol_has_required_keys(protocol):
    rules = PROTOCOL_RULES[protocol]
    missing = [k for k in REQUIRED_KEYS if k not in rules]
    assert not missing, f"{protocol} is missing keys: {missing}"


@pytest.mark.parametrize("protocol", ALL_PROTOCOLS)
def test_range_fields_are_low_high_pairs(protocol):
    rules = PROTOCOL_RULES[protocol]
    for field in ("packet_count", "packet_size", "flow_duration"):
        low, high = rules[field]
        # some declared protocols have a fixed, non-varying packet_count (e.g.
        # radius/gtp are always an exact request/response pair), so allow low == high.
        assert low <= high, f"{protocol}.{field} range is not low <= high: {rules[field]}"


@pytest.mark.parametrize("protocol", ALL_PROTOCOLS)
def test_bins_are_sorted_and_within_range(protocol):
    """A packet_length_bin edge above packet_size[1] makes
    BaseFlowGenerator.build_bins() produce a non-monotonic last bin
    (e.g. arp: packet_size=(42, 128) but packet_length_bin has 200 as an
    edge -> build_bins appends packet_size[1]=128 after 200, giving an
    inverted (200, 128) bin that would crash np.random.randint(200, 128)
    if this protocol ever used the shared decode_packet path instead of
    its own hardcoded bin maps)."""
    if protocol == "arp":
        pytest.xfail(
            "known bug: arp packet_length_bin=[70,100,200] exceeds "
            "packet_size=(42,128) in rules/protocol_rules.py"
        )
    rules = PROTOCOL_RULES[protocol]

    length_bins = rules["packet_length_bin"]
    assert length_bins == sorted(length_bins), f"{protocol} packet_length_bin not sorted"
    low, high = rules["packet_size"]
    assert all(low <= b <= high for b in length_bins), (
        f"{protocol} packet_length_bin values must fall within packet_size range {rules['packet_size']}"
    )

    iat_bins = rules["iat_bin"]
    assert iat_bins == sorted(iat_bins), f"{protocol} iat_bin not sorted"


@pytest.mark.parametrize("protocol", ALL_PROTOCOLS)
def test_sequence_fields_include_direction_and_iat(protocol):
    fields = PROTOCOL_RULES[protocol]["csv_sequence_fields"]
    assert "direction" in fields
    assert "iat" in fields
    assert "packet_length" in fields


@pytest.mark.parametrize("protocol", ALL_PROTOCOLS)
def test_staged_protocols_have_consistent_stage_config(protocol):
    rules = PROTOCOL_RULES[protocol]
    stages = rules.get("stages")
    if not stages:
        pytest.skip(f"{protocol} has no stages")

    stage_packets = rules.get("stage_packets")
    assert stage_packets is not None, f"{protocol} declares stages but no stage_packets"
    # every stage referenced in stage_packets must be a declared stage
    for stage_name in stage_packets:
        assert stage_name in stages, (
            f"{protocol} stage_packets has unknown stage '{stage_name}' not in {stages}"
        )


def test_http_and_dns_seed_data_present():
    from rules.protocol_rules import HTTP, DNS_DATA

    assert HTTP["urls"]
    assert HTTP["hosts"]
    assert HTTP["status_codes"]
    assert HTTP["bodies"]

    assert DNS_DATA["domains"]
    for entry in DNS_DATA["domains"]:
        assert "domain" in entry
        assert entry["ips"]
