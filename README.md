# traffic_simulator

This repository generates synthetic network traffic (PCAP files) from **declared protocol specs** — plain YAML files describing a protocol's message sequence, timing and packet sizes. No real capture, dataset extraction, or model training is required to add or use a protocol.

## Purpose

- Generate synthetic traffic straight from a declared protocol (`protocols/<name>.yaml`)
- Generate a multi-protocol traffic mix from a declared scenario (`scenarios/<name>.yaml`)
- Evaluate generated output against real captures (optional)
- *(legacy, optional)* Preprocess real PCAPs and train statistical models (copula/HMM) for protocols that don't have a hand-declared spec yet

## Requirements

- Python 3.10+ or Python 3.11
- Windows / Linux / macOS
- Internet access to install Python packages

## Installation

1. Create and activate a virtual environment:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

3. Optional: install the package to enable the `traffic` command:

```powershell
python -m pip install -e .
```

> If you prefer not to install the package, you can still run commands directly with `python cli.py <command> [options]`.

## Main structure

- `cli.py` - main CLI entrypoint
- `protocols/` - **declared protocol specs** (message sequence, direction, size/IAT ranges) — the source of truth for generation
- `scenarios/` - scenario YAML definitions + loader (multi-protocol traffic mixes)
- `generation/` - synthetic traffic generation (`declarative_generator.py` builds sequences from `protocols/*.yaml`; `<X>_generator.py` turns a sequence into real Scapy packets)
- `rules/` - protocol rules (field names/order used by both generation and the legacy extraction pipeline)
- `evaluator/` - evaluation tools
- `data/` - *(legacy)* sample PCAP data
- `dataset/` - *(legacy)* extracted flow and sequence datasets
- `preprocessing/` - *(legacy)* feature extraction from real PCAPs
- `training/` - *(legacy)* flow and sequence model training (copula/HMM)
- `models/` - *(legacy)* trained models

## Usage

From the repository root, run either:

```powershell
traffic <command> [options]
```

or directly:

```powershell
python cli.py <command> [options]
```

### 1. Generate synthetic traffic for one protocol

```powershell
traffic generate -p dns --n 10
```

- `-p/--protocol`: protocol name — any name with a `protocols/<name>.yaml` spec. Ships with `arp`, `icmp`, `dns`, `dhcp`, `tcp`, `http` (generic networking) and `isup`, `sip`, `rtp`, `radius`, `gtp`, `map`, `diameter` (telecom: PSTN signaling, VoIP call setup + media, AAA, mobile core tunneling, 2G/3G/4G subscriber location update)
- `--n/--num`: number of flows to generate (default 10)

Output PCAP is written to `output/{protocol}_flow.pcap`. This needs nothing but the spec file — no PCAP capture, no dataset, no trained model.

```powershell
traffic protocol list
traffic protocol show --name isup
```

#### Declaring a new protocol

Create `protocols/<name>.yaml`. `sequence` is an ordered list of message steps; a step can be wrapped in a `repeat` block to get a random number of repetitions (e.g. a ping burst, or a variable number of TCP data exchanges):

```yaml
name: my_protocol
description: "What this protocol's traffic looks like"
sequence:
  - message: 1          # value written into the protocol-specific field
    direction: 0         # 0 = initiator -> responder, 1 = responder -> initiator
    packet_length: [60, 120]
    iat: [0.001, 0.05]
  - repeat:
      count: [1, 5]       # random repeat count per flow
      messages:
        - message: 2
          direction: 1
          packet_length: [60, 120]
          iat: [0.001, 0.2]
```

`message` is written into whichever field `PROTOCOL_RULES[protocol]["csv_sequence_fields"]` (in `rules/protocol_rules.py`) names besides `direction`/`packet_length`/`iat` (e.g. `dhcp_msg_type`, `tcp_flags`, `isup_msg_type`). If the protocol doesn't have a `PROTOCOL_RULES` entry yet, add one (ranges/bins from that entry aren't used for generation anymore, but `csv_sequence_fields` still defines the field name and column order).

Actually turning a declared sequence into bytes on the wire still needs a small amount of protocol-specific Python — add a `generation/<Name>_generator.py` with a `BaseFlowGenerator` subclass implementing `build_packets(self, all_df, base_time)` (see `generation/ICMP_generator.py` for the simplest example), and register it in `generation/__init__.py`. No ML code, no `decode_packet`/model loading needed — `build_packets` just reads the declared fields straight off each row.

Once both files exist, the protocol works immediately in `traffic generate -p <name>` and in any scenario YAML.

### 2. Generate traffic from a scenario

A **scenario** is a named mix of protocols (with per-protocol flow counts) merged into a single output PCAP with one consistent timeline. Scenarios are plain YAML files in `scenarios/` — adding a new scenario never requires touching Python code.

```powershell
traffic scenario list
traffic scenario show --name office_browsing
traffic scenario generate --name office_browsing
traffic scenario generate --name office_browsing --out output/my_run.pcap
```

`traffic scenario list` prints every `scenarios/*.yaml` file's name and description. `generate` builds each component protocol's flows straight from its `protocols/<name>.yaml` spec, merges every protocol's packets onto one shared timeline, sorts them, and writes one PCAP.

#### Adding a new scenario

Create `scenarios/<name>.yaml`:

```yaml
name: my_scenario
description: "What this traffic mix represents"
components:
  - protocol: dns
    num_flows: 20
  - protocol: http
    num_flows: 10
output: "output/scenario_my_scenario.pcap"
```

Every `protocol` must have a `protocols/<name>.yaml` spec (see "Declaring a new protocol" above). No code changes needed — and no data collection or training either.

### 3. Filter PCAP

```powershell
traffic fillter -p dhcp --m "message" --i raw_data/dhcp.pcapng
```

- `--m/--message`: filter expression similar to tshark
- `--p/--protocol`: protocol name
- `--i/--input`: input PCAP file path (optional)

### 4. *(Legacy, optional)* Calibrate from real captures

Generation (`traffic generate`, `traffic scenario generate`) never needs this — it only reads `protocols/*.yaml`. This pipeline still exists for anyone who wants to statistically calibrate a protocol against real traffic instead of hand-declaring its ranges: extract a real PCAP into flow/sequence datasets, then train a copula (flow-level) and HMM (sequence-level) model from them.

```powershell
traffic extract -p dns
traffic extract -p dns --path data/dns_pcap.pcap   # or extract a custom PCAP file
traffic train -p dns
```

`extract` writes CSVs under `dataset/{protocol}/` (or `output/output_dataset/` when using `--path`). `train` fits `training/flow_training.py` (VineCopula) and `training/sequences_training.py` (HMM) and saves to `models/`. Nothing in the current `generate`/`scenario` code path reads these models anymore.

## Notes

- The repository uses `setup.py` to register the `traffic` console script.
- Installing the package is optional; if `traffic` is unavailable, use `python cli.py <command> [options]`.
- `protocols/*.yaml` and `scenarios/*.yaml` are the two files you'll actually edit day to day. `data/`, `dataset/`, `models/`, `preprocessing/`, `training/` only matter if you use the legacy calibration pipeline (section 4 above).

## Testing

The `tests/` directory holds a pytest suite covering: protocol spec loading/validation (`protocols/*.yaml`), the declarative sequence generator, packet parsing, protocol handlers, flow building/cleaning, extraction, per-protocol `build_packets()`, scenario loading/merging, the legacy training pipeline (using the real checked-in datasets/models), evaluation, and the CLI end-to-end.

```powershell
python -m pip install -r requirements.txt
python -m pytest
```

Tests that touch the filesystem run inside a scratch directory (see the `isolated_cwd`/`isolated_cwd_no_models` fixtures in `tests/conftest.py`) so they never write into the real `dataset/`, `models/`, or `output/` folders — `isolated_cwd_no_models` specifically proves generation works with no `models/` directory present at all. A few tests intentionally assert on **known bugs** still present in the legacy extraction pipeline (documented in each test's docstring) so they double as a bug tracker; those either expect a specific exception or are marked `xfail`.

## Reference

Generation pipeline: `protocols/*.yaml` → `declarative_generator` → `<X>_generator.build_packets()` → PCAP (optionally merged by `scenarios/*.yaml` + `ScenarioRunner`).

Legacy calibration pipeline (optional): `preprocessing` → `dataset` → `training` → `models/`.
