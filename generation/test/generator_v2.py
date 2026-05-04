import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import hashlib
import pickle
import pandas as pd
import os
import numpy as np
from rules.protocol_rules import PROTOCOL_RULES


class GeneratorV2:
    protocol = ""
    registry = None
    flows_model = None
    generator = None

    def __init__(self, protocol, registry):
        self.registry = registry
        self.protocol = protocol
        self.flows_model = pickle.load(open(f"models/flow_models/{self.protocol}_flow.pkl", "rb"))
        self.generator = self.registry.get_generator_handler(self.protocol)

    def set_protocol(self, protocol):
        self.protocol = protocol
        self.flows_model = pickle.load(open(f"models/flow_models/{protocol}_flow.pkl", "rb"))
        self.generator = self.registry.get_generator_handler(protocol)

    def _get_flow_seed(self, num_flows):
        key = f"{self.protocol}:{num_flows}"
        return int(hashlib.md5(key.encode("utf-8")).hexdigest()[:8], 16)

    def generate_flows_features(self, num_flows):
        seed = self._get_flow_seed(num_flows)
        np.random.seed(seed)

        model = self.flows_model
        X_sample = model.sample(num_flows)

        rules = PROTOCOL_RULES[self.protocol]

        df = pd.DataFrame(X_sample, columns=[
            "flow_duration",
            "packet_count",
            "total_bytes",
        ])

        df["flow_duration"] = np.expm1(df["flow_duration"]).abs()
        df["packet_count"] = np.expm1(df["packet_count"]).abs().astype(int).clip(*rules["packet_count"])
        df.loc[df["packet_count"] < 1, "packet_count"] = 1

        df["total_bytes"] = np.expm1(df["total_bytes"]).abs().round().astype(int)
        min_total = df["packet_count"] * rules["packet_size"][0]
        max_total = df["packet_count"] * rules["packet_size"][1]
        df["total_bytes"] = df["total_bytes"].clip(min_total, max_total)

        df["avg_packet_size"] = (df["total_bytes"] / df["packet_count"].replace(0, 1)).clip(*rules["packet_size"])
        df["total_bytes"] = (df["avg_packet_size"] * df["packet_count"]).round().astype(int)

        df["packet_rate"] = df["packet_count"] / df["flow_duration"].replace(0, 1e-6)
        df["iat_mean"] = df["flow_duration"] / df["packet_count"].replace(0, 1)

        return df

    def generate_sequences_features(self, flow_features):
        if isinstance(flow_features, pd.Series):
            flow_features = flow_features.to_dict()

        packet_count = int(flow_features.get("packet_count", 0))
        packet_count = max(packet_count, 1)

        df = self.generator.generate_sequences(packet_count)
        df = self.adjust_sequence_with_flow(df, flow_features)

        return df

    def adjust_sequence_with_flow(self, df, flow_features):
        if df is None or df.empty:
            return df

        rules = PROTOCOL_RULES[self.protocol]
        requested_count = int(flow_features.get("packet_count", len(df)))
        actual_count = len(df)
        flow_duration = float(flow_features.get("flow_duration", df["iat"].sum() if "iat" in df else 1.0))
        avg_packet_size = float(flow_features.get("avg_packet_size", df["packet_length"].mean() if "packet_length" in df else 64))
        total_bytes = float(flow_features.get("total_bytes", requested_count * avg_packet_size))

        if requested_count > 0 and requested_count != actual_count:
            total_bytes = float(np.round(total_bytes * actual_count / requested_count))

        df = df.copy()

        if "packet_length" in df.columns:
            packet_length = self.generate_packet_lengths(
                actual_count,
                avg_packet_size,
                total_bytes,
                rules["packet_size"],
                base_lengths=df["packet_length"].values
            )
            df["packet_length"] = packet_length

        if "iat" in df.columns:
            iat = self.generate_iat_sequence(
                actual_count,
                flow_duration,
                rules.get("iat", (0.000001, 1)),
                base_iat=df["iat"].values
            )
            df["iat"] = iat

        return df

    def generate_packet_lengths(self, packet_count, avg_packet_size, total_bytes, size_bounds, base_lengths=None):
        min_size, max_size = size_bounds
        avg_packet_size = np.clip(avg_packet_size, min_size, max_size)

        lengths = None
        if base_lengths is not None:
            base = np.asarray(base_lengths, dtype=float)
            base = np.nan_to_num(base, nan=avg_packet_size, posinf=avg_packet_size, neginf=avg_packet_size)
            base = np.clip(base, min_size, max_size)
            if base.size == packet_count and base.sum() > 0:
                mean_base = max(base.mean(), 1.0)
                scaled_base = base * (avg_packet_size / mean_base)
                lengths = np.clip(np.round(scaled_base), min_size, max_size).astype(int)

        if lengths is None or lengths.sum() == 0:
            lengths = np.full(packet_count, int(np.round(avg_packet_size)), dtype=int)

        target_sum = int(max(total_bytes, packet_count * min_size))
        current_sum = int(np.sum(lengths))
        if current_sum <= 0:
            current_sum = 1

        weights = lengths.astype(float) / current_sum
        scaled = np.floor(weights * target_sum).astype(int)

        diff = target_sum - scaled.sum()
        if diff > 0:
            order = np.argsort(-weights)
            idx = 0
            while diff > 0 and idx < packet_count:
                pos = order[idx]
                if scaled[pos] < max_size:
                    scaled[pos] += 1
                    diff -= 1
                idx += 1
                if idx == packet_count:
                    idx = 0
                    if np.all(scaled >= max_size):
                        break

        scaled = np.clip(scaled, min_size, max_size)
        if scaled.sum() != target_sum:
            diff = target_sum - scaled.sum()
            idx = 0
            while diff != 0 and packet_count > 0:
                if diff > 0 and scaled[idx] < max_size:
                    scaled[idx] += 1
                    diff -= 1
                elif diff < 0 and scaled[idx] > min_size:
                    scaled[idx] -= 1
                    diff += 1
                idx = (idx + 1) % packet_count
                if idx == 0 and np.all((scaled == min_size) | (scaled == max_size)):
                    break

        return scaled

    def generate_iat_sequence(self, packet_count, flow_duration, iat_bounds, base_iat=None):
        min_iat, max_iat = iat_bounds
        flow_duration = max(flow_duration, packet_count * min_iat)
        mean_iat = flow_duration / packet_count

        iat = None
        if base_iat is not None:
            iat = np.asarray(base_iat, dtype=float)
            iat = np.nan_to_num(iat, nan=mean_iat, posinf=max_iat, neginf=min_iat)
            iat = np.clip(iat, min_iat, max_iat)
            if iat.size != packet_count or iat.sum() <= 0:
                iat = None

        if iat is None:
            iat = np.full(packet_count, mean_iat, dtype=float)

        total = float(np.sum(iat))
        if total <= 0:
            total = 1.0
        iat = iat * (flow_duration / total)
        iat = np.clip(iat, min_iat, max_iat)

        current_sum = float(iat.sum())
        if abs(current_sum - flow_duration) > 1e-12:
            diff = flow_duration - current_sum
            if diff > 0:
                order = np.argsort(-iat)
                for idx in order:
                    if diff <= 0:
                        break
                    available = max_iat - iat[idx]
                    if available <= 0:
                        continue
                    delta = min(available, diff)
                    iat[idx] += delta
                    diff -= delta
            else:
                order = np.argsort(iat)
                for idx in order:
                    if diff >= 0:
                        break
                    available = iat[idx] - min_iat
                    if available <= 0:
                        continue
                    delta = min(available, -diff)
                    iat[idx] -= delta
                    diff += delta

        if iat.sum() == 0:
            iat = np.full(packet_count, mean_iat, dtype=float)

        return iat

    def export_pcap(self, all_flows, output_path):
        self.generator.to_pcap(all_flows, output_path)
