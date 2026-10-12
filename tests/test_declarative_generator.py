import random

from generation.declarative_generator import generate_flow_sequence
from generation.protocol_spec import load_protocol_spec


def test_generate_flow_sequence_arp_has_fixed_two_step_order():
    spec = load_protocol_spec("arp")
    df = generate_flow_sequence("arp", spec)

    assert len(df) == 2
    assert list(df["direction"]) == [0, 1]
    assert list(df["arp_opcode"]) == [1, 2]
    assert (df["packet_length"] >= 42).all() and (df["packet_length"] <= 60).all()
    assert (df["iat"] >= 0.0001).all() and (df["iat"] <= 0.01).all()


def test_generate_flow_sequence_dhcp_is_always_discover_offer_request_ack():
    spec = load_protocol_spec("dhcp")
    df = generate_flow_sequence("dhcp", spec)

    assert list(df["dhcp_msg_type"]) == [1, 2, 3, 5]
    assert list(df["direction"]) == [0, 1, 0, 1]


def test_generate_flow_sequence_icmp_repeat_block_varies_length():
    spec = load_protocol_spec("icmp")

    lengths = {len(generate_flow_sequence("icmp", spec)) for _ in range(30)}

    # repeat count is [1,5] pairs -> 2,4,6,8,10 packets; over 30 draws we
    # should see more than one distinct length (proves repeat is randomized).
    assert lengths <= {2, 4, 6, 8, 10}
    assert len(lengths) > 1
    for length in lengths:
        assert length % 2 == 0


def test_generate_flow_sequence_icmp_alternates_request_reply_within_each_pair():
    spec = load_protocol_spec("icmp")
    df = generate_flow_sequence("icmp", spec)

    directions = list(df["direction"])
    types = list(df["icmp_type"])
    for i in range(0, len(directions), 2):
        assert directions[i] == 0 and types[i] == 8
        assert directions[i + 1] == 1 and types[i + 1] == 0


def test_generate_flow_sequence_isup_setup_and_cleanup_are_fixed_active_varies():
    spec = load_protocol_spec("isup")
    df = generate_flow_sequence("isup", spec)

    messages = list(df["isup_msg_type"])
    assert messages[0] == "IAM"
    assert messages[1] == "ACM"
    assert messages[-2] == "REL"
    assert messages[-1] == "RLC"
    # everything between ACM and REL must be ANM (the repeated "active" stage)
    assert all(m == "ANM" for m in messages[2:-2])


def test_generate_flow_sequence_map_location_update_is_fixed_four_step():
    spec = load_protocol_spec("map")
    df = generate_flow_sequence("map", spec)

    assert list(df["map_msg_type"]) == [
        "UPDATE_LOCATION",
        "INSERT_SUBSCRIBER_DATA",
        "INSERT_SUBSCRIBER_DATA_ACK",
        "UPDATE_LOCATION_ACK",
    ]
    assert list(df["direction"]) == [0, 1, 0, 1]


def test_generate_flow_sequence_diameter_ulr_ula_pair():
    spec = load_protocol_spec("diameter")
    df = generate_flow_sequence("diameter", spec)

    assert list(df["diameter_cmd"]) == ["ULR", "ULA"]
    assert list(df["direction"]) == [0, 1]


def test_generate_flow_sequence_gtp_echo_then_location_update():
    spec = load_protocol_spec("gtp")
    df = generate_flow_sequence("gtp", spec)

    assert list(df["gtp_type"]) == [1, 2, 18, 19]


def test_generate_flow_sequence_tcp_handshake_then_data_then_close():
    spec = load_protocol_spec("tcp")
    df = generate_flow_sequence("tcp", spec)

    flags = list(df["tcp_flags"])
    assert flags[0] == 2    # SYN
    assert flags[1] == 18   # SYN-ACK
    assert flags[2] == 16   # ACK
    assert flags[-2] == 17  # FIN-ACK
    assert flags[-1] == 16  # ACK
    assert all(f == 24 for f in flags[3:-2])  # data stage is all PSH-ACK


def test_generate_flow_sequence_columns_match_csv_sequence_fields():
    from rules.protocol_rules import PROTOCOL_RULES

    for protocol in ["arp", "icmp", "dns", "dhcp", "isup", "tcp", "http", "sip", "radius", "gtp", "rtp", "map", "diameter"]:
        spec = load_protocol_spec(protocol)
        df = generate_flow_sequence(protocol, spec)
        assert list(df.columns) == list(PROTOCOL_RULES[protocol]["csv_sequence_fields"])


def test_generate_flow_sequence_is_randomized_across_calls():
    spec = load_protocol_spec("arp")
    lengths = {tuple(generate_flow_sequence("arp", spec)["packet_length"]) for _ in range(20)}
    assert len(lengths) > 1
