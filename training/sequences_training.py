

# # import pandas as pd
# # protocol = "http"
# # df = pd.read_csv(f"dataset/{protocol}_sequences_dataset.csv")

# # # combine direction + tcp_flags thành 1 state
# # df["state"] = df["direction"].astype(str) + "_" + df["tcp_flags"].astype(str)

# # # encode thành số
# # state_map = {s: i for i, s in enumerate(df["state"].unique())}
# # inv_state_map = {i: s for s, i in state_map.items()}

# # df["state_id"] = df["state"].map(state_map)
# # import numpy as np

# # features_cont = ["iat", "packet_length"]

# # seq_cont = []
# # seq_disc = []
# # lengths = []

# # for flow_id, group in df.groupby("flow_id"):
# #     group = group.sort_index()

# #     cont = group[features_cont].values
# #     disc = group["state_id"].values.reshape(-1, 1)

# #     seq_cont.append(cont)
# #     seq_disc.append(disc)
# #     lengths.append(len(group))

# # X_cont = np.vstack(seq_cont)
# # X_disc = np.vstack(seq_disc)

# # from sklearn.preprocessing import StandardScaler

# # scaler = StandardScaler()
# # X_cont = scaler.fit_transform(X_cont)

# # from hmmlearn.hmm import GaussianHMM, CategoricalHMM

# # # -------- Continuous HMM --------
# # hmm_cont = GaussianHMM(
# #     n_components=5,
# #     covariance_type="diag",
# #     n_iter=200,
# #     random_state=42
# # )

# # hmm_cont.fit(X_cont, lengths)


# # # -------- Discrete HMM --------
# # hmm_disc = CategoricalHMM(
# #     n_components=5,
# #     n_iter=200,
# #     random_state=42
# # )

# # hmm_disc.fit(X_disc, lengths)

# # import joblib

# # joblib.dump(hmm_cont, f"models/sequences_models/{protocol}/{protocol}_sequences_hmm_cont.pkl")
# # joblib.dump(hmm_disc, f"models/sequences_models/{protocol}/{protocol}_sequences_hmm_disc.pkl")
# # joblib.dump(scaler, f"models/sequences_models/{protocol}/{protocol}_sequences_scaler.pkl")
# # joblib.dump(state_map, f"models/sequences_models/{protocol}/{protocol}_sequences_state_map.pkl")
# # joblib.dump(inv_state_map, f"models/sequences_models/{protocol}/{protocol}_sequences_inv_state_map.pkl")

# import sys
# import os

# sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# import pandas as pd
# import numpy as np
# import joblib
# import os

# from sklearn.preprocessing import StandardScaler
# from hmmlearn.hmm import GaussianHMM, CategoricalHMM

# from rules.protocol_rules import PROTOCOL_RULES

# class SequenceHMMTrainer:

#     def __init__(self, protocol, rules, dataset_dir="dataset", model_dir="models/sequences_models"):
#         self.protocol = protocol
#         self.rules = rules
#         self.dataset_path = f"{dataset_dir}/{protocol}_sequences_dataset.csv"
#         self.model_dir = f"{model_dir}/{protocol}"
#         self.stages = PROTOCOL_RULES[protocol].get("stages")

#         os.makedirs(self.model_dir, exist_ok=True)

#     def set_dataset_path(self,path):
#         self.dataset_path = path
#     # -----------------------------
#     # LOAD DATA
#     # -----------------------------
#     def load_data(self):
#         df = pd.read_csv(self.dataset_path)
#         return df

#     # -----------------------------
#     # PREPARE FEATURES
#     # -----------------------------
#     def prepare_features(self, df):
#         seq_fields = self.rules["csv_sequence_fields"]

        
#         cont_fields = ["iat", "packet_length"]

        
#         disc_fields = [f for f in seq_fields if f not in cont_fields]

       
#         df["state"] = df[disc_fields].astype(str).agg("_".join, axis=1)
        

#         # encode
#         state_map = {s: i for i, s in enumerate(df["state"].unique())}
#         inv_state_map = {i: s for s, i in state_map.items()}

#         df["state_id"] = df["state"].map(state_map)

#         n_states = df["state_id"].nunique()

#         n_components = min(5, n_states)

#         return df, cont_fields, disc_fields, state_map, inv_state_map, n_components

#     # -----------------------------
#     # BUILD SEQUENCES
#     # -----------------------------
#     def build_sequences(self, df, cont_fields):
#         seq_cont = []
#         seq_disc = []
#         lengths = []

#         for flow_id, group in df.groupby("flow_id"):
#             group = group.sort_index()

#             cont = group[cont_fields].values
#             disc = group["state_id"].values.reshape(-1, 1)

#             seq_cont.append(cont)
#             seq_disc.append(disc)
#             lengths.append(len(group))

#         X_cont = np.vstack(seq_cont)
#         X_disc = np.vstack(seq_disc)

#         return X_cont, X_disc, lengths

#     # -----------------------------
#     # TRAIN
#     # -----------------------------
#     def train(self, stage=None, path=None):
#         if path:
#             self.set_dataset_path(path)

#         df = self.load_data()
        
#         # df["packet_length"] += np.random.randint(-10, 10, size=len(df))
#         # df["iat"] += np.random.uniform(0, 0.005, size=len(df))

#         # df["packet_length"] = np.log1p(df["packet_length"])

#         if df.empty:
#             print(f"Skip {stage} (empty dataset)")
#             return

#         df, cont_fields, disc_fields, state_map, inv_state_map, n_components = self.prepare_features(df)

#         X_cont, X_disc, lengths = self.build_sequences(df, cont_fields)

#         scaler = StandardScaler()
#         X_cont = scaler.fit_transform(X_cont)

#         # -------- HMM CONT --------
#         hmm_cont = GaussianHMM(
#             n_components=n_components,
#             # covariance_type="full",
#             covariance_type="diag",
#             n_iter=200,
#             tol=1e-2,
#             # min_covar=1e-2,
#             random_state=42
#         )
#         hmm_cont.fit(X_cont, lengths)

#         #extra
#         # hmm_cont.covars_ = np.maximum(hmm_cont.covars_, 1e-2)

#         # -------- HMM DISC --------
#         hmm_disc = CategoricalHMM(
#             n_components=n_components,
#             n_iter=200,
#             random_state=42
#         )
#         hmm_disc.fit(X_disc, lengths)

#         # -------- FIX transmat --------
#         transmat = hmm_disc.transmat_
#         for i in range(transmat.shape[0]):
#             row_sum = transmat[i].sum()
#             if row_sum == 0:
#                 transmat[i] = np.ones(transmat.shape[1]) / transmat.shape[1]
#             else:
#                 transmat[i] /= row_sum
#         hmm_disc.transmat_ = transmat

#         # -------- FIX startprob --------
#         startprob = hmm_disc.startprob_
#         if startprob.sum() == 0:
#             startprob = np.ones_like(startprob) / len(startprob)
#         else:
#             startprob /= startprob.sum()
#         hmm_disc.startprob_ = startprob

#         # -------- SAVE --------
#         model_path = f"{self.model_dir}/{self.protocol}"
#         if stage:
#             model_path = f"{self.model_dir}/{stage}/{self.protocol}_{stage}"

#         joblib.dump(hmm_cont, f"{model_path}_hmm_cont.pkl")
#         joblib.dump(hmm_disc, f"{model_path}_hmm_disc.pkl")
#         joblib.dump(scaler, f"{model_path}_scaler.pkl")
#         joblib.dump(state_map, f"{model_path}_state_map.pkl")
#         joblib.dump(inv_state_map, f"{model_path}_inv_state_map.pkl")

#         print(f"Trained {model_path}")
#     def train_by_stage(self):
#         if not self.stages:
#             print("protocol don't have stages")
#             return
        
#         for s in self.stages:
#             os.makedirs(f"{self.model_dir}/{s}", exist_ok=True)
#             self.train(s,f"dataset/{self.protocol}_{s}_sequences_dataset.csv")


# if __name__== "__main__":
    

#     protocols = ["http"]

#     for proto in protocols:
#         trainer = SequenceHMMTrainer(
#             protocol=proto,
#             rules=PROTOCOL_RULES[proto]
#         )
#         # trainer.train()
#         trainer.train_by_stage()

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

        df["packet_length_bin"] = np.digitize(
            df["packet_length"],
            bins=[70, 100, 200]
        )

        df["iat_bin"] = np.digitize(
            df["iat"],
            bins=[0.0001, 0.01, 0.1]
        )

        # 👉 ALL DISCRETE
        disc_fields = [
            "direction",
            "tcp_flags",
            "packet_length_bin",
            "iat_bin"
        ]

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
            self.train(s, f"dataset/{self.protocol}_{s}_sequences_dataset.csv")


if __name__ == "__main__":

    protocols = ["http"]

    for proto in protocols:
        trainer = SequenceHMMTrainer(
            protocol=proto,
            rules=PROTOCOL_RULES[proto]
        )
        trainer.train_by_stage()