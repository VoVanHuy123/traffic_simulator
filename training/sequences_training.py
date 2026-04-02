

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import pandas as pd
import numpy as np
import joblib

from hmmlearn.hmm import CategoricalHMM
from rules.protocol_rules import PROTOCOL_RULES


class SequenceHMMTrainer:

    def __init__(self, protocol, rules, dataset_dir="dataset", model_dir="models/sequences_models"):
        self.protocol = protocol
        self.rules = rules
        self.dataset_path = f"{dataset_dir}/{protocol}_sequences_dataset.csv"
        self.model_dir = f"{model_dir}/{protocol}"
        self.stages = PROTOCOL_RULES[protocol].get("stages")
        self.packet_length_bin = None
        self.iat_bin = None

        os.makedirs(self.model_dir, exist_ok=True)

    def set_dataset_path(self, path):
        self.dataset_path = path

    # -----------------------------
    # LOAD
    # -----------------------------
    def load_data(self):
        return pd.read_csv(self.dataset_path)

    # -----------------------------
    # FEATURE ENGINEERING (KEY)
    # -----------------------------
    def prepare_features(self, df):


        self.packet_length_bin = PROTOCOL_RULES.get(self.protocol).get("packet_length_bin")
        self.iat_bin = PROTOCOL_RULES.get(self.protocol).get("iat_bin")
        df["packet_length_bin"] = np.digitize(
            df["packet_length"],
            bins=self.packet_length_bin
        )

        df["iat_bin"] = np.digitize(
            df["iat"],
            bins=self.iat_bin
        )

        seq_fields = PROTOCOL_RULES.get(self.protocol).get("csv_sequence_fields")
        cont_fields = ["iat", "packet_length"]
        disc_fields = [f for f in seq_fields if f not in cont_fields]

        disc_fields.append("packet_length_bin")
        disc_fields.append("iat_bin")
        
        
        # tạo state
        df["state"] = df[disc_fields].astype(str).agg("_".join, axis=1)

        # encode
        state_map = {s: i for i, s in enumerate(df["state"].unique())}
        inv_state_map = {i: s for s, i in state_map.items()}

        df["state_id"] = df["state"].map(state_map)

        n_states = df["state_id"].nunique()
        n_components = min(5, n_states)

        return df, state_map, inv_state_map, n_components

    # -----------------------------
    # BUILD SEQUENCE
    # -----------------------------
    def build_sequences(self, df):
        seq_disc = []
        lengths = []

        for _, group in df.groupby("flow_id"):
            group = group.sort_index()
            disc = group["state_id"].values.reshape(-1, 1)

            seq_disc.append(disc)
            lengths.append(len(group))

        X_disc = np.vstack(seq_disc)

        return X_disc, lengths

    # -----------------------------
    # TRAIN
    # -----------------------------
    def train(self, stage=None, path=None):

        if path:
            self.set_dataset_path(path)

        df = self.load_data()

        if df.empty:
            print(f"Skip {stage}")
            return

        df, state_map, inv_state_map, n_components = self.prepare_features(df)
        X_disc, lengths = self.build_sequences(df)

        hmm = CategoricalHMM(
            n_components=n_components,
            n_iter=200
        )

        hmm.fit(X_disc, lengths)

        # fix transmat
        transmat = hmm.transmat_
        for i in range(transmat.shape[0]):
            if transmat[i].sum() == 0:
                transmat[i] = np.ones(transmat.shape[1]) / transmat.shape[1]
            else:
                transmat[i] /= transmat[i].sum()
        hmm.transmat_ = transmat

        # fix startprob
        startprob = hmm.startprob_
        if startprob.sum() == 0:
            startprob = np.ones_like(startprob) / len(startprob)
        else:
            startprob /= startprob.sum()
        hmm.startprob_ = startprob

        # save
        model_path = f"{self.model_dir}/{self.protocol}"
        if stage:
            os.makedirs(f"{self.model_dir}/{stage}", exist_ok=True)
            model_path = f"{self.model_dir}/{stage}/{self.protocol}_{stage}"

        joblib.dump(hmm, f"{model_path}_hmm.pkl")
        joblib.dump(state_map, f"{model_path}_state_map.pkl")
        joblib.dump(inv_state_map, f"{model_path}_inv_state_map.pkl")

        print(f"Trained {model_path}")

    def train_by_stage(self):
        if not self.stages:
            print("No stages")
            return

        for s in self.stages:
            self.train(s, f"dataset/{self.protocol}/{self.protocol}_{s}_sequences_dataset.csv")

