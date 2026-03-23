# import pickle
# import numpy as np
# import joblib
# import pandas as pd


# protocol = "http"
# # Load model
# model = joblib.load(f"models/sequences_models/{protocol}sequences_model.pkl")
# scaler = joblib.load(f"models/sequences_models/{protocol}sequences_scaler.pkl")

# # Generate 10 packets
# X_gen, _ = model.sample(10)

# # Inverse scale
# X_gen = scaler.inverse_transform(X_gen)

# generated_df = pd.DataFrame(
#     X_gen,
#     columns=["iat", "packet_length", "direction", "tcp_flags"]
# )

# print(generated_df)









# import joblib
# import pandas as pd
# protocol = "http"
# hmm_cont = joblib.load(f"models/sequences_models/{protocol}/{protocol}_sequences_hmm_cont.pkl")
# hmm_disc = joblib.load(f"models/sequences_models/{protocol}/{protocol}_sequences_hmm_disc.pkl")
# scaler = joblib.load(f"models/sequences_models/{protocol}/{protocol}_sequences_scaler.pkl")
# # joblib.load(f"models/sequences_models/{protocol}/{protocol}_sequences_state_map.pkl")
# inv_state_map = joblib.load(f"models/sequences_models/{protocol}/{protocol}_sequences_inv_state_map.pkl")


# n_packets = 10

# # sample
# Xc, _ = hmm_cont.sample(n_packets)
# Xd, _ = hmm_disc.sample(n_packets)

# # inverse scale
# Xc = scaler.inverse_transform(Xc)

# # decode state
# states = [inv_state_map[int(s[0])] for s in Xd]

# directions = []
# tcp_flags = []

# for s in states:
#     d, f = s.split("_")
#     directions.append(int(d))
#     tcp_flags.append(int(f))

# # build dataframe
# gen_df = pd.DataFrame({
#     "iat": Xc[:, 0],
#     "packet_length": Xc[:, 1],
#     "direction": directions,
#     "tcp_flags": tcp_flags
# })
# gen_df["iat"] = gen_df["iat"].clip(lower=1e-6)  
# gen_df["packet_length"] = gen_df["packet_length"].clip(lower=40, upper=1500)
# gen_df["packet_length"] = gen_df["packet_length"].round().astype(int)
# gen_df.loc[0, ["direction", "tcp_flags"]] = [0, 2]    # SYN
# gen_df.loc[1, ["direction", "tcp_flags"]] = [1, 18]   # SYN-ACK
# gen_df.loc[2, ["direction", "tcp_flags"]] = [0, 16] 
# print(gen_df)













# import numpy as np
# import pandas as pd
# import joblib


# class TCPFlowGenerator:
#     def __init__(self, protocol="http", model_dir="models/sequences_models"):
#         self.protocol = protocol

#         self.hmm_cont = joblib.load(f"{model_dir}/{protocol}/{protocol}_sequences_hmm_cont.pkl")
#         self.scaler = joblib.load(f"{model_dir}/{protocol}/{protocol}_sequences_scaler.pkl")

#     # -----------------------------
#     # TCP NEXT FLAG (no FIN early)
#     # -----------------------------
#     def next_flag(self, current_flag, stage):
#         if stage == "HANDSHAKE":
#             if current_flag == 2:
#                 return 18
#             elif current_flag == 18:
#                 return 16

#         elif stage == "DATA":
#             return np.random.choice([16, 24], p=[0.6, 0.4])

#         elif stage == "CLOSING":
#             if current_flag != 17:
#                 return 17  # force FIN
#             else:
#                 return None

#     # -----------------------------
#     # HTTP LOGIC
#     # -----------------------------
#     def generate_packet(self, flag):
#         pkt = {}

#         if flag == 2:
#             pkt["direction"] = 0
#             pkt["packet_length"] = 60

#         elif flag == 18:
#             pkt["direction"] = 1
#             pkt["packet_length"] = 60

#         elif flag == 16:
#             pkt["direction"] = np.random.choice([0, 1])
#             pkt["packet_length"] = 40

#         elif flag == 24:
#             # HTTP behavior
#             if np.random.rand() < 0.7:
#                 pkt["direction"] = 1  # server response
#                 pkt["packet_length"] = int(np.random.normal(1000, 200))
#             else:
#                 pkt["direction"] = 0  # client request
#                 pkt["packet_length"] = int(np.random.normal(300, 100))

#         elif flag == 17:
#             pkt["direction"] = np.random.choice([0, 1])
#             pkt["packet_length"] = 40

#         pkt["packet_length"] = int(np.clip(pkt["packet_length"], 40, 1500))
#         pkt["tcp_flags"] = flag

#         return pkt

#     # -----------------------------
#     # MAIN GENERATOR (PRO)
#     # -----------------------------
#     def generate_flow(self, n_packets=12):
#         Xc, _ = self.hmm_cont.sample(n_packets)
#         Xc = self.scaler.inverse_transform(Xc)

#         packets = []

#         # -----------------------------
#         # STAGE 1: HANDSHAKE
#         # -----------------------------
#         stage = "HANDSHAKE"
#         handshake_flags = [2, 18, 16]

#         for i, flag in enumerate(handshake_flags):
#             pkt = self.generate_packet(flag)
#             pkt["iat"] = max(Xc[i][0], 1e-6)
#             packets.append(pkt)

#         current_flag = 16

#         # -----------------------------
#         # STAGE 2: DATA
#         # -----------------------------
#         stage = "DATA"
#         data_end = int(n_packets * 0.8)

#         for i in range(3, data_end):
#             next_flag = self.next_flag(current_flag, stage)

#             pkt = self.generate_packet(next_flag)
#             pkt["iat"] = max(Xc[i][0], 1e-6)

#             packets.append(pkt)
#             current_flag = next_flag

#         # -----------------------------
#         # STAGE 3: CLOSING
#         # -----------------------------
#         stage = "CLOSING"

#         for i in range(data_end, n_packets):
#             next_flag = self.next_flag(current_flag, stage)

#             if next_flag is None:
#                 break

#             pkt = self.generate_packet(next_flag)
#             pkt["iat"] = max(Xc[i][0], 1e-6)

#             packets.append(pkt)
#             current_flag = next_flag

#         # -----------------------------
#         # FINAL ACK after FIN
#         # -----------------------------
#         if packets[-1]["tcp_flags"] == 17:
#             packets.append({
#                 "iat": 0.001,
#                 "packet_length": 40,
#                 "direction": 1 - packets[-1]["direction"],
#                 "tcp_flags": 16
#             })

#         return pd.DataFrame(packets)





from TCP_generator import HTTPFlowGenerator
from UDP_generator import DNSFlowGenerator,DHCPFlowGenerator
from ICMP_generator import ICMPFlowGenerator
from ARP_generator import ARPFlowGenerator
class FlowGeneratorFactory:

    @staticmethod
    def create(protocol):
        if protocol == "http":
            return HTTPFlowGenerator(protocol)
        elif protocol == "dns":
            return DNSFlowGenerator(protocol)
        elif protocol == "dhcp":
            return DHCPFlowGenerator(protocol)
        elif protocol == "icmp":
            return ICMPFlowGenerator(protocol)
        elif protocol == "arp":
            return ARPFlowGenerator(protocol)
        else:
            raise ValueError("Unsupported protocol")

if __name__ == "__main__":
    gen = FlowGeneratorFactory.create("http")
    df = gen.generate_flow(12)

    print(df)
