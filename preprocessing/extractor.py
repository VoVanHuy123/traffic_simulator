import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from rules.protocol_rules import PROTOCOL_RULES
import numpy as np
from .dataset_exporter import DatasetExporter
class Extractor:
    exporter = DatasetExporter()
    def __init__(self,protocol):
        self.protocol = protocol
    def set_protocol(self,protocol):
        self.protocol = protocol
    def extract_basic_sequences_features(self,pkt, prev_time):
        feature_map = {}

        timestamp = float(pkt.time)

        if prev_time is None:
            feature_map["iat"] = 0
        else:
            feature_map["iat"] = timestamp - prev_time

        feature_map["packet_length"] = len(pkt)
        return feature_map, timestamp    
    
    def extract(self, flow,prev_time):

        rows = []
        prev_time = prev_time

        handler = flow["handler"]

        for pkt in flow["packets"]:

            row = {}

            row["packet_length"] = len(pkt)

            if prev_time:
                row["iat"] = pkt.time - prev_time
            else:
                row["iat"] = 0

            row.update(handler.extract_flags(pkt))

            prev_time = pkt.time
            rows.append(row)

        return rows, prev_time
    
    def extract_flow_diration_and_iat_mean(self,flow):
        packets = sorted(flow["packets"], key=lambda x: x.time)
        times = [float(pkt.time) for pkt in packets]
        flow_duration,iat_mean =0,0
        if len(times) > 1:
            flow_duration = times[-1] - times[0]
            iat = np.diff(times)
            iat_mean = float(np.mean(iat))
        else:
            flow_duration = 0
            iat_mean = 0
        
        return flow_duration,iat_mean
    
    def extract_total_bytes_and_avg_packet_size(self,flow):
        packets = sorted(flow["packets"], key=lambda x: x.time)
        sizes = [len(pkt) for pkt in packets]
        total_bytes = sum(sizes)
        avg_packet_size = float(np.mean(sizes)) if sizes else 0

        return total_bytes, avg_packet_size
    
    def extract_flow_features(self,flows,output_csv_path):
        rows = []
        headers = None
        csv_feature_fields = PROTOCOL_RULES[self.protocol]["csv_feature_fields"]

        for flow in flows:
            packets = sorted(flow["packets"], key=lambda x: x.time)
            protocol = flow["protocol"]
            key_dict = flow["key_dict"]

            packet_count = len(packets)

            total_bytes, avg_packet_size = self.extract_total_bytes_and_avg_packet_size(flow)
            flow_duration , iat_mean = self.extract_flow_diration_and_iat_mean(flow)

            # flow_duration = np.log1p(flow_duration)
            # packet_count = np.log1p(packet_count)
            # avg_packet_size = np.log1p(avg_packet_size)
            # iat_mean = np.log1p(iat_mean)
            # total_bytes = np.log1p(total_bytes)

            feature_dict = {
                **key_dict,
                "packet_count": packet_count,
                "total_bytes": total_bytes,
                "avg_packet_size": avg_packet_size,
                "flow_duration": flow_duration,
                "iat_mean": iat_mean
            
            }

             # init header 
            if headers is None:
                headers = list(csv_feature_fields)

            row = [feature_dict.get(f, None) for f in csv_feature_fields]

            rows.append(row)
        self.exporter.export_dataset(rows,csv_feature_fields,output_csv_path,flow_id=False)
            
    def extract_sequences_features(self,flows, output_csv):
        rows = []
        flow_id = 0
        seq_fields = PROTOCOL_RULES[self.protocol]["csv_sequence_fields"]

        for flow in flows:
            packets = sorted(flow["packets"], key=lambda x: x.time)
            protocol = flow["protocol"]
            key_dict  = flow["key_dict"]
            protocol_handler = flow["handler"]
            if protocol not in PROTOCOL_RULES:
                continue

           
            times = [float(pkt.time) for pkt in packets]
            if len(times) <= 1:
                continue

            last_time = times[0]
            for i, pkt in enumerate(packets):
                feature_map = {}
                basic_feat, last_time = self.extract_basic_sequences_features(pkt,last_time)
                feature_map.update(basic_feat)

                feature_map.update(protocol_handler.extract_direction(pkt,key_dict))

                feature_map.update(protocol_handler.extract_flags(pkt))

                row = [flow_id]
                for field in seq_fields:
                    field = field.strip()
                    row.append(feature_map.get(field, 0))

                rows.append(row)

            flow_id += 1

        self.exporter.export_dataset(rows,seq_fields,output_csv)

    
    def extract_sequences_by_stages(self,flows, output_csv):
        rows ={}
        seq_fields = PROTOCOL_RULES[self.protocol]["csv_sequence_fields"]
        stages = PROTOCOL_RULES[self.protocol].get("stages")

        for s in stages:
            rows[s] = []

        flow_id = 0
        for flow in flows:
            protocol = flow["protocol"]
            protocol_handler = flow["handler"]
            key_dict  = flow["key_dict"]
            if protocol not in ["tcp","http", "https"]:
                continue
            packets = sorted(flow["packets"], key=lambda x: x.time)
            if len(packets) < 3:
                continue

            if protocol not in PROTOCOL_RULES:
                continue
        
            stage_pkts = protocol_handler.get_ptks_by_stages(flow)
            has_any_stage = False  
            for s in stages:
                pkts = stage_pkts.get(s, [])

                if not pkts:
                    continue

                has_any_stage = True

                last_time = float(pkts[0].time)

                for j, pkt in enumerate(pkts):
                    feature_map = {}
                    basic_feat, last_time = self.extract_basic_sequences_features(pkt,last_time)
                    feature_map.update(basic_feat)

                    feature_map.update(protocol_handler.extract_direction(pkt,key_dict))

                    feature_map.update(protocol_handler.extract_flags(pkt))

                    row = [flow_id]
                    for field in seq_fields:
                        field = field.strip()
                        row.append(feature_map.get(field, 0))

                    rows[s].append(row)

            if has_any_stage:
                flow_id += 1
        self.exporter.export_dataset_by_stage(self.protocol,rows,seq_fields,stages)








