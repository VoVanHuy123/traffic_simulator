# import sys
# import os

# sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from preprocessing import ExtractRegistry
from .flow_builder import FlowBuilder
from .flow_cleaner import FlowCleaner
from .extractor import Extractor


def main():
    protocol = "http"
    input_pcap_path = f"data/{protocol}_pcap.pcap"

    builder = FlowBuilder(ExtractRegistry)
    flows = builder.build(input_pcap_path)

    cleaner = FlowCleaner(protocol)
    flows = cleaner.clean(flows)

    extractor = Extractor(protocol)

    extractor.extract_flow_features(
        flows,
        f"dataset/{protocol}_flow_dataset.csv"
    )

    extractor.extract_sequences_by_stages(
        flows,
        "ff"
    )
if __name__ == "__main__":
    main()

    