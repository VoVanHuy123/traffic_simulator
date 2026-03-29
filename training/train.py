import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import os
from rules.protocol_rules import PROTOCOL_RULES

from flow_training import FlowTrainer
from sequences_training import SequenceHMMTrainer

if __name__ == "__main__":
    protocols = ["dhcp"]
    for proto in protocols:
        # train flow
        flows_trainer = FlowTrainer(
            protocol=proto,
            dataset_path=f"dataset/{proto}_flow_dataset.csv",
            model_path=f"dataset/{proto}_flow_dataset.csv"
        )
        flows_trainer.model_train()

        # train sequences
        sequences_trainer = SequenceHMMTrainer(
            protocol=proto,
            rules=PROTOCOL_RULES[proto]
        )
        have_stages = PROTOCOL_RULES[proto].get("stages")
        if have_stages:
            sequences_trainer.train_by_stage()
        else:
            sequences_trainer.train()