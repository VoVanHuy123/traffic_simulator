from scapy.all import Ether, rdpcap

from generation.scenario_runner import ScenarioRunner


def _small_scenario(output_path):
    return {
        "name": "test_mix",
        "components": [
            {"protocol": "icmp", "num_flows": 3},
            {"protocol": "arp", "num_flows": 3},
        ],
        "output": output_path,
    }


def test_scenario_runner_merges_protocols_into_one_pcap(isolated_cwd):
    scenario = _small_scenario("output/test_mix.pcap")

    out_path = ScenarioRunner().run(scenario)

    packets = rdpcap(out_path)
    assert len(packets) > 0

    has_arp = any(p.haslayer("ARP") for p in packets)
    has_icmp = any(p.haslayer("ICMP") for p in packets)
    assert has_arp and has_icmp


def test_scenario_runner_output_is_time_sorted(isolated_cwd):
    scenario = _small_scenario("output/test_mix_sorted.pcap")
    out_path = ScenarioRunner().run(scenario)

    packets = rdpcap(out_path)
    times = [float(p.time) for p in packets]
    assert times == sorted(times)


def test_scenario_runner_normalizes_every_packet_to_ethernet(isolated_cwd):
    """arp/dhcp build Ether-framed packets while icmp/dns/tcp/http build bare
    IP packets; merging them into one classic PCAP requires one consistent
    linktype or packets decode incorrectly on read-back."""
    scenario = _small_scenario("output/test_mix_linktype.pcap")
    out_path = ScenarioRunner().run(scenario)

    packets = rdpcap(out_path)
    assert all(p.haslayer(Ether) for p in packets)


def test_scenario_runner_does_not_require_models_directory(isolated_cwd_no_models):
    scenario = _small_scenario("output/no_models.pcap")
    out_path = ScenarioRunner().run(scenario)

    packets = rdpcap(out_path)
    assert len(packets) > 0


def test_scenario_runner_creates_missing_output_directory(isolated_cwd):
    scenario = _small_scenario("output/nested/dir/test_mix.pcap")
    out_path = ScenarioRunner().run(scenario)

    assert (isolated_cwd / "output" / "nested" / "dir" / "test_mix.pcap").exists()
    assert out_path == "output/nested/dir/test_mix.pcap"
