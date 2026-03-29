import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import joblib
import numpy as np
import pandas as pd
from scapy.all import rdpcap,wrpcap

from rules.protocol_rules import PROTOCOL_RULES
from generation.TCP_generator import TCPFlowGenerator,HTTPFlowGenerator
from generation.UDP_generator import DNSFlowGenerator,DHCPFlowGenerator
from generation.ARP_generator import ARPFlowGenerator
from generation.ICMP_generator import ICMPFlowGenerator
from generation.base_generator import BaseFlowGenerator
from generation.flows_generate import generate_flow
from preprocessing.data_clean import filter_valid_ack
if __name__=="__main__":

    protocol = "http"
    df = generate_flow(protocol,6)
    # gen = ICMPFlowGenerator(protocol)
    gen = HTTPFlowGenerator()
    gen.set_model("handshake")
    all_flows=[]
    for index, row in df.iterrows():
        print(f"== flow {index +1}")
        df = gen.generate_sequences(int(row["packet_count"]))
        all_flows.append(df)
        print(df)
    gen.to_pcap(all_flows,f"output/{protocol}_flow.pcap")


    