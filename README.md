# traffic_simulator

This repository contains a pipeline to generate synthetic network traffic from real PCAP data.

## Purpose

- Preprocess PCAP files
- Extract flow and sequence datasets
- Train flow and sequence models
- Generate synthetic traffic
- Evaluate generated output

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
- `data/` - sample PCAP data
- `dataset/` - extracted flow and sequence datasets
- `preprocessing/` - feature extraction from PCAP
- `training/` - flow and sequence model training
- `generation/` - synthetic traffic generation
- `models/` - stored trained models
- `evaluator/` - evaluation tools
- `rules/` - protocol rules

## Usage

From the repository root, run either:

```powershell
traffic <command> [options]
```

or directly:

```powershell
python cli.py <command> [options]
```

### 1. Generate synthetic traffic

```powershell
traffic generate -p dns --n 10
```

- `-p/--protocol`: protocol name (examples: `http`, `dns`, `icmp`, `tcp`, `dhcp`, `arp`)
- `--n/--num`: number of flows to generate (default 10)

Output PCAP is written to `output/{protocol}_flow.pcap`.

### 2. Extract dataset from PCAP

```powershell
traffic extract -p dns
```

Or with a custom PCAP file:

```powershell
traffic extract -p dns --path data/dns_pcap.pcap
```

Results are saved under `dataset/{protocol}/`, or under `output/output_dataset/` when using `--path`.

### 3. Train models

```powershell
traffic train -p dns
```

This command trains both the flow and sequence models for the specified protocol.

### 4. Filter PCAP

```powershell
traffic fillter -p dhcp --m "message" --i raw_data/dhcp.pcapng
```

- `--m/--message`: filter expression similar to tshark
- `--p/--protocol`: protocol name
- `--i/--input`: input PCAP file path (optional)

## Notes

- The repository uses `setup.py` to register the `traffic` console script.
- Installing the package is optional; if `traffic` is unavailable, use `python cli.py <command> [options]`.
- Default sample data and outputs are located in `data/`, `dataset/`, and `output/`.

## Reference

Core pipeline: `preprocessing` → `dataset` → `training` → `generation` → `evaluator`.
