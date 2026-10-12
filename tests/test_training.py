import numpy as np
import pandas as pd
import pytest

from training.flow_training import FlowTrainer
from training.sequences_training import SequenceHMMTrainer
from rules.protocol_rules import PROTOCOL_RULES


def test_flow_trainer_load_flow_data_filters_to_protocol_rules(repo_root):
    # icmp/dns/tcp's checked-in flow_dataset.csv files hold stale, already
    # log1p-transformed packet_count values (e.g. dns packet_count sits
    # between 1.09 and 1.39, i.e. log1p(2)..log1p(3)) which fall outside the
    # rules' raw ranges and filter down to zero rows. http's dataset is raw
    # and matches the current schema, so use it here instead.
    trainer = FlowTrainer(
        protocol="http",
        dataset_path=str(repo_root / "dataset" / "http" / "http_flow_dataset.csv"),
    )
    df = trainer._load_flow_data()

    rules = PROTOCOL_RULES["http"]
    assert len(df) > 0
    assert (df["packet_count"] >= rules["packet_count"][0]).all()
    assert (df["packet_count"] <= rules["packet_count"][1]).all()
    assert (df["flow_duration"] >= rules["flow_duration"][0]).all()
    assert (df["flow_duration"] <= rules["flow_duration"][1]).all()


def test_flow_trainer_model_train_produces_loadable_sampler(repo_root, tmp_path):
    model_path = tmp_path / "http_flow.pkl"
    trainer = FlowTrainer(
        protocol="http",
        dataset_path=str(repo_root / "dataset" / "http" / "http_flow_dataset.csv"),
        model_path=str(model_path),
    )

    trainer.model_train()

    assert model_path.exists()

    import pickle
    with open(model_path, "rb") as f:
        model = pickle.load(f)

    sample = model.sample(3)
    assert len(sample) == 3


def test_sequence_hmm_trainer_prepare_features_builds_state_ids():
    trainer = SequenceHMMTrainer(protocol="icmp", rules=PROTOCOL_RULES["icmp"])

    df = pd.DataFrame({
        "flow_id": [0, 0, 1, 1],
        "iat": [0.001, 0.02, 0.001, 0.5],
        "packet_length": [60, 90, 60, 150],
        "direction": [0, 1, 0, 1],
        "icmp_type": [8, 0, 8, 0],
    })

    prepared, state_map, inv_state_map, n_components = trainer.prepare_features(df)

    assert "state_id" in prepared.columns
    assert set(prepared["state_id"]) == set(state_map.values())
    assert all(inv_state_map[i] == s for s, i in state_map.items())
    assert 1 <= n_components <= 5


def test_sequence_hmm_trainer_train_produces_valid_hmm(repo_root, tmp_path):
    trainer = SequenceHMMTrainer(
        protocol="icmp",
        rules=PROTOCOL_RULES["icmp"],
        dataset_dir=str(repo_root / "dataset"),
        model_dir=str(tmp_path / "seq_models"),
    )

    trainer.train()

    model_dir = tmp_path / "seq_models" / "icmp"
    assert (model_dir / "icmp_hmm.pkl").exists()
    assert (model_dir / "icmp_state_map.pkl").exists()
    assert (model_dir / "icmp_inv_state_map.pkl").exists()

    import joblib
    hmm = joblib.load(model_dir / "icmp_hmm.pkl")

    # every row of the transition matrix and the start distribution must be a
    # valid probability distribution (this is exactly what train() patches up
    # for states hmmlearn couldn't observe often enough to fit on its own)
    assert np.allclose(hmm.transmat_.sum(axis=1), 1.0)
    assert np.isclose(hmm.startprob_.sum(), 1.0)


def test_sequence_hmm_trainer_train_by_stage_skips_when_no_stages():
    trainer = SequenceHMMTrainer(protocol="icmp", rules=PROTOCOL_RULES["icmp"])
    # icmp has no "stages" entry -- train_by_stage should just no-op, not raise
    trainer.train_by_stage()
