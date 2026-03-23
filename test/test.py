import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import joblib
import numpy as np
import pandas as pd
from scapy.all import rdpcap,wrpcap


from generation.TCP_generator import TCPFlowGenerator,HTTPFlowGenerator
from generation.flows_generate import generate_flow
from preprocessing.data_clean import filter_valid_ack
if __name__=="__main__":
    df = generate_flow("http",6)
    gen = HTTPFlowGenerator("http")
    all_flows=[]
    for index, row in df.iterrows():
        print(f"== flow {index +1}")
        sdf = gen.generate_protocol_sequences( int(row["packet_count"]))
        
        all_flows.append(sdf)
        print(sdf)

    gen.to_pcap(all_flows, "output/http_flow.pcap")



    # packets = rdpcap("data/http_pcap.pcap")
    # data = filter_valid_ack(packets)
    # wrpcap("data/http.pcap",data)


    