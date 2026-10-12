import pytest

from generation.protocol_spec import ProtocolSpecError, list_protocol_specs, load_protocol_spec


def test_list_protocol_specs_includes_shipped_protocols():
    names = {s["name"] for s in list_protocol_specs()}
    assert {"arp", "icmp", "dns", "dhcp", "isup", "tcp", "http", "sip", "radius", "gtp", "rtp", "map", "diameter"} <= names


def test_list_protocol_specs_have_descriptions():
    for s in list_protocol_specs():
        assert s["description"], f"protocol {s['name']} has no description"


@pytest.mark.parametrize("name", ["arp", "icmp", "dns", "dhcp", "isup", "tcp", "http", "sip", "radius", "gtp", "rtp", "map", "diameter"])
def test_load_protocol_spec_returns_valid_sequence(name):
    spec = load_protocol_spec(name)

    assert spec["name"] == name
    assert spec["sequence"]

    for step in spec["sequence"]:
        if "repeat" in step:
            repeat = step["repeat"]
            assert len(repeat["count"]) == 2
            assert repeat["count"][0] <= repeat["count"][1]
            assert repeat["messages"]
            for msg in repeat["messages"]:
                assert msg["direction"] in (0, 1)
        else:
            assert step["direction"] in (0, 1)
            assert len(step["packet_length"]) == 2
            assert len(step["iat"]) == 2


def test_load_protocol_spec_unknown_name_raises_with_available_list():
    with pytest.raises(ProtocolSpecError) as exc_info:
        load_protocol_spec("not_a_real_protocol")

    message = str(exc_info.value)
    assert "not_a_real_protocol" in message
    assert "arp" in message


def test_validate_spec_rejects_empty_sequence(tmp_path, monkeypatch):
    import generation.protocol_spec as spec_module

    (tmp_path / "broken.yaml").write_text("name: broken\ndescription: no sequence\n")
    monkeypatch.setattr(spec_module, "SPECS_DIR", str(tmp_path))

    with pytest.raises(ProtocolSpecError, match="sequence"):
        spec_module.load_protocol_spec("broken")


def test_validate_spec_rejects_invalid_direction(tmp_path, monkeypatch):
    import generation.protocol_spec as spec_module

    (tmp_path / "broken2.yaml").write_text(
        "name: broken2\n"
        "sequence:\n"
        "  - message: 1\n"
        "    direction: 2\n"
        "    packet_length: [40, 60]\n"
        "    iat: [0.001, 0.01]\n"
    )
    monkeypatch.setattr(spec_module, "SPECS_DIR", str(tmp_path))

    with pytest.raises(ProtocolSpecError, match="direction"):
        spec_module.load_protocol_spec("broken2")


def test_validate_spec_rejects_inverted_range(tmp_path, monkeypatch):
    import generation.protocol_spec as spec_module

    (tmp_path / "broken3.yaml").write_text(
        "name: broken3\n"
        "sequence:\n"
        "  - message: 1\n"
        "    direction: 0\n"
        "    packet_length: [100, 40]\n"
        "    iat: [0.001, 0.01]\n"
    )
    monkeypatch.setattr(spec_module, "SPECS_DIR", str(tmp_path))

    with pytest.raises(ProtocolSpecError, match="packet_length"):
        spec_module.load_protocol_spec("broken3")


def test_validate_spec_rejects_repeat_without_messages(tmp_path, monkeypatch):
    import generation.protocol_spec as spec_module

    (tmp_path / "broken4.yaml").write_text(
        "name: broken4\n"
        "sequence:\n"
        "  - repeat:\n"
        "      count: [1, 3]\n"
        "      messages: []\n"
    )
    monkeypatch.setattr(spec_module, "SPECS_DIR", str(tmp_path))

    with pytest.raises(ProtocolSpecError, match="messages"):
        spec_module.load_protocol_spec("broken4")
