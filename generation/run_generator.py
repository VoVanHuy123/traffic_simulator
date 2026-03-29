from generation import GenRegistry
from .generator import Generator

def main():
    protocol = "dns"

    generator = Generator(protocol,GenRegistry)
    df_flows = generator.generate_flows_features(6)

    all_flows = []
    for index, row in df_flows.iterrows():
        print(f"== flow {index +1}")
        df = generator.generate_sequences_features(row["packet_count"])
        all_flows.append(df)
        print(df)
    
    generator.export_pcap(all_flows,f"output/{protocol}_flow.pcap")

if __name__ == "__main__":
    main()