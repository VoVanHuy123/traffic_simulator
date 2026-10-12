import pytest

from scenarios.loader import ScenarioError, list_scenarios, load_scenario


def test_list_scenarios_includes_shipped_examples():
    names = {s["name"] for s in list_scenarios()}
    assert {"office_browsing", "network_scan", "voip_signaling", "dhcp_bootstrap", "voip_call", "radius_auth", "mobile_data_session", "location_update"} <= names


def test_list_scenarios_have_non_empty_descriptions():
    for s in list_scenarios():
        assert s["description"], f"scenario {s['name']} has no description"


@pytest.mark.parametrize("name", ["office_browsing", "network_scan", "voip_signaling", "dhcp_bootstrap", "voip_call", "radius_auth", "mobile_data_session", "location_update"])
def test_load_scenario_returns_valid_component_list(name):
    scenario = load_scenario(name)

    assert scenario["name"] == name
    assert scenario["output"]
    assert scenario["components"]
    for comp in scenario["components"]:
        assert comp["protocol"]
        assert isinstance(comp["num_flows"], int)
        assert comp["num_flows"] > 0


def test_load_scenario_unknown_name_raises_with_available_list():
    with pytest.raises(ScenarioError) as exc_info:
        load_scenario("this_scenario_does_not_exist")

    message = str(exc_info.value)
    assert "this_scenario_does_not_exist" in message
    assert "office_browsing" in message


def test_validate_scenario_rejects_unknown_protocol(tmp_path, monkeypatch):
    import scenarios.loader as loader_module

    bad_scenario_dir = tmp_path
    (bad_scenario_dir / "broken.yaml").write_text(
        "name: broken\n"
        "description: bad protocol\n"
        "components:\n"
        "  - protocol: not_a_real_protocol\n"
        "    num_flows: 5\n"
        "output: output/broken.pcap\n"
    )
    monkeypatch.setattr(loader_module, "SCENARIOS_DIR", str(bad_scenario_dir))

    with pytest.raises(ScenarioError, match="Unknown protocol"):
        loader_module.load_scenario("broken")


def test_validate_scenario_rejects_missing_num_flows(tmp_path, monkeypatch):
    import scenarios.loader as loader_module

    (tmp_path / "broken2.yaml").write_text(
        "name: broken2\n"
        "description: missing num_flows\n"
        "components:\n"
        "  - protocol: dns\n"
        "output: output/broken2.pcap\n"
    )
    monkeypatch.setattr(loader_module, "SCENARIOS_DIR", str(tmp_path))

    with pytest.raises(ScenarioError, match="num_flows"):
        loader_module.load_scenario("broken2")


def test_validate_scenario_rejects_missing_components(tmp_path, monkeypatch):
    import scenarios.loader as loader_module

    (tmp_path / "broken3.yaml").write_text(
        "name: broken3\n"
        "description: no components\n"
        "output: output/broken3.pcap\n"
    )
    monkeypatch.setattr(loader_module, "SCENARIOS_DIR", str(tmp_path))

    with pytest.raises(ScenarioError, match="components"):
        loader_module.load_scenario("broken3")
