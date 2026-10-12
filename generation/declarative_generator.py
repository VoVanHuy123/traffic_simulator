import random

import pandas as pd

from rules.protocol_rules import PROTOCOL_RULES


def _expand_sequence(sequence):
    """Flatten a spec's `sequence` (which may contain `repeat` blocks) into a
    plain, ordered list of message steps."""
    steps = []
    for item in sequence:
        if "repeat" in item:
            repeat = item["repeat"]
            low, high = repeat["count"]
            count = random.randint(int(low), int(high))
            for _ in range(count):
                steps.extend(repeat["messages"])
        else:
            steps.append(item)
    return steps


def generate_flow_sequence(protocol, spec):
    """Build one flow's per-packet sequence DataFrame directly from a declared
    protocol spec (see protocols/<name>.yaml) -- no trained model involved.
    Column order matches PROTOCOL_RULES[protocol]["csv_sequence_fields"] so it
    is a drop-in replacement for what the old HMM-based generate() produced,
    and generation/<X>_generator.py's build_packets() needs no changes.
    """
    seq_fields = PROTOCOL_RULES[protocol]["csv_sequence_fields"]
    msg_field = next(f for f in seq_fields if f not in ("iat", "packet_length", "direction"))

    rows = []
    for step in _expand_sequence(spec["sequence"]):
        length_low, length_high = step["packet_length"]
        packet_length = random.randint(int(length_low), int(length_high))

        iat_low, iat_high = step["iat"]
        iat = random.uniform(iat_low, iat_high)

        values = {
            "direction": step["direction"],
            "packet_length": packet_length,
            "iat": iat,
            msg_field: step["message"],
        }
        rows.append({field: values[field] for field in seq_fields})

    return pd.DataFrame(rows, columns=list(seq_fields))
