PROTOCOL_RULES = {

    "dns": {
        "packet_count": (2, 6),

        "packet_size": (60, 512),

        "flow_duration": (0.001, 0.5),

        "flow_key": (
            "src_ip", "dst_ip", "src_port", "dst_port", "transport", "protocol","id"
        ),

        "csv_feature_fields": (
            "src_ip", "dst_ip", "packet_count", "flow_duration", "avg_packet_size"
        ),
        "csv_sequence_fields": (
            "iat",
            "packet_length",
            "direction",
            "dns_type"
        ),
        "cleaning_rules": {
            "max_flow_duration": 2,
            "max_iat": 1,
            "min_packets": 2,
            "required_structure": "query_response",  
        }
    },

    "http": {
        "packet_count": (4, 1000),
        "max_packets":1000,

        "packet_size": (40, 1500),

        "flow_duration": (0.01, 120),

        "flow_key": (
            "src_ip", "dst_ip", "src_port", "dst_port", "transport", "protocol"
        ),

        "csv_feature_fields": (
            "src_ip", "dst_ip", "src_port", "dst_port",
            "flow_duration", "packet_count", "total_bytes", "avg_packet_size"
        ),
        "csv_sequence_fields": (
            "iat",
            "packet_length",
            "direction",
            "tcp_flags",
        ),
        "cleaning_rules": {
            "max_flow_duration": 120,
            "max_iat": 10,
            "min_packets": 4,
            "require_syn": True,
            "require_payload": True,
        },
        "stages":["handshake","closing","data"],
        "stage_packets":{
            "handshake": 3,
            "closing":2
        }
    },
    "https": {
        "packet_count": (4, 1000),
        "max_packets":1000,

        "packet_size": (40, 1500),

        "flow_duration": (0.01, 120),

        "flow_key": (
            "src_ip", "dst_ip", "src_port", "dst_port", "transport", "protocol"
        ),

        "csv_feature_fields": (
            "src_ip", "dst_ip", "src_port", "dst_port",
            "flow_duration", "packet_count", "total_bytes", "avg_packet_size"
        ),
        "csv_sequence_fields": (
            "iat",
            "packet_length",
            "direction",
            "tcp_flags"
        ),
        "cleaning_rules": {
            "max_flow_duration": 120,
            "max_iat": 10,
            "min_packets": 4,
            "require_syn": True,
            "require_payload": True,
        }
    },

    "icmp": {
        "packet_count": (1, 20),

        "packet_size": (56, 256),

        "flow_duration": (0.001, 2),

        "flow_key": (
            "protocol","src_ip", "dst_ip", "icmp_id","transport"
        ),

        "csv_feature_fields": (
            "src_ip", "dst_ip", "packet_count", "flow_duration", "avg_packet_size"
        ),
        "csv_sequence_fields": (
            "iat",
            "packet_length",
            "direction",
            "icmp_type"
        ),
        "cleaning_rules": {
            "max_flow_duration": 5,
            "max_iat": 2,
            "min_packets": 2,
            "required_types": [8, 0], 
        }
    },

    "dhcp": {
        "packet_count": (2, 6),

        "packet_size": (240, 400),

        "flow_duration": (0.01, 5),

        "flow_key": (
            "protocol",
            "xid"
        ),

        "csv_feature_fields": (
            "xid", "packet_count", "flow_duration", "avg_packet_size"
        ),
        "csv_sequence_fields": (
            "iat",
            "packet_length",
            "direction",
            "dhcp_msg_type"
        ),
        "cleaning_rules": {
            "max_flow_duration": 10,
            "max_iat": 5,
            "min_packets": 4,
            "required_states": [1, 2, 3, 5],
        },
        "stages":["discover","offer","request","ack"]
    },
    "arp": {
        "packet_count": (1, 4),

        "packet_size": (42, 128),

        "flow_duration": (0.0005, 1),

        "flow_key": (
            "src_ip",
            "dst_ip",
            "protocol"
        ),

        "csv_feature_fields": (
            "src_ip",
            "dst_ip",
            "packet_count",
            "flow_duration",
            "avg_packet_size"
        ),
        "csv_sequence_fields": (
            "iat",
            "packet_length",
            "direction",
            "arp_opcode"
        ),
        "cleaning_rules": {
            "max_flow_duration": 2,
            "max_iat": 1,
            "min_packets": 1,
            "required_opcodes": [1, 2],  
        }
    }
}
