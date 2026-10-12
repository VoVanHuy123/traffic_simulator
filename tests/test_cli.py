import sys

import cli
from scapy.all import rdpcap


def test_generate_protocol_writes_output_pcap(isolated_cwd):
    cli.generate_protocol("icmp", 2)

    packets = rdpcap("output/icmp_flow.pcap")
    assert len(packets) > 0


def test_scenario_list_prints_all_scenario_names(capsys):
    cli.scenario_list()
    out = capsys.readouterr().out
    assert "office_browsing" in out
    assert "network_scan" in out


def test_scenario_show_prints_yaml_for_valid_name(capsys):
    cli.scenario_show("office_browsing")
    out = capsys.readouterr().out
    assert "office_browsing" in out
    assert "components" in out


def test_scenario_show_prints_error_for_unknown_name(capsys):
    cli.scenario_show("nope_not_real")
    out = capsys.readouterr().out
    assert "Error" in out


def test_scenario_generate_writes_merged_pcap(isolated_cwd, capsys):
    cli.scenario_generate("network_scan")

    packets = rdpcap("output/scenario_network_scan.pcap")
    assert len(packets) > 0


def test_scenario_generate_respects_out_override(isolated_cwd):
    cli.scenario_generate("voip_signaling", out="output/custom_name.pcap")

    packets = rdpcap("output/custom_name.pcap")
    assert len(packets) > 0


def test_main_generate_subcommand_end_to_end(isolated_cwd, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["traffic", "generate", "-p", "icmp", "--n", "2"])
    cli.main()

    packets = rdpcap("output/icmp_flow.pcap")
    assert len(packets) > 0


def test_main_scenario_generate_subcommand_end_to_end(isolated_cwd, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["traffic", "scenario", "generate", "--name", "dhcp_bootstrap"])
    cli.main()

    packets = rdpcap("output/scenario_dhcp_bootstrap.pcap")
    assert len(packets) > 0


def test_protocol_list_prints_all_protocol_names(capsys):
    cli.protocol_list()
    out = capsys.readouterr().out
    assert "arp" in out
    assert "isup" in out


def test_protocol_show_prints_yaml_for_valid_name(capsys):
    cli.protocol_show("dhcp")
    out = capsys.readouterr().out
    assert "dhcp" in out
    assert "sequence" in out


def test_protocol_show_prints_error_for_unknown_name(capsys):
    cli.protocol_show("nope_not_real")
    out = capsys.readouterr().out
    assert "Error" in out


def test_main_protocol_list_subcommand(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["traffic", "protocol", "list"])
    cli.main()
    out = capsys.readouterr().out
    assert "tcp" in out


def test_generate_protocol_does_not_require_models_directory(isolated_cwd_no_models):
    """Confirms the CLI-level generate path also has no ML dependency."""
    cli.generate_protocol("dhcp", 2)

    packets = rdpcap("output/dhcp_flow.pcap")
    assert len(packets) > 0


def test_main_scenario_with_no_action_prints_usage(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["traffic", "scenario"])
    cli.main()

    out = capsys.readouterr().out
    assert "Usage" in out


def test_extract_command_crashes_for_non_staged_protocol(isolated_cwd, repo_root):
    """Reproduces a real bug in cli.py's `extract`: for a protocol without
    `stages` (e.g. icmp), it unconditionally calls
    `extractor.extract_sequences_features()` with zero arguments, but that
    method requires (flows, output_csv). `traffic extract -p icmp` currently
    always raises TypeError."""
    import pytest

    (isolated_cwd / "dataset" / "icmp").mkdir(parents=True)
    (isolated_cwd / "data").mkdir()
    import shutil
    shutil.copy(repo_root / "data" / "icmp_pcap.pcap", isolated_cwd / "data" / "icmp_pcap.pcap")

    with pytest.raises(TypeError):
        cli.extract("icmp")
