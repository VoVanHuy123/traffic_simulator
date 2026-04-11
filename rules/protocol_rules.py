PROTOCOL_RULES = {

    "dns": {
        "packet_count": (2, 6),

        "packet_size": (60, 512),

        "flow_duration": (0.001, 0.5),
        "iat":(0.000001, 1),
        "flow_key": (
            "src_ip", "dst_ip", "src_port", "dst_port", "transport", "protocol","id"
        ),

        "csv_feature_fields": (
            "src_ip", "dst_ip", "packet_count", "flow_duration", "avg_packet_size","iat_mean","total_bytes"
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
        },
         "packet_length_bin":[80, 100, 200],
        "iat_bin":[0.0001, 0.01, 0.1],
        "evaluation_features":[ "packet_count","flow_duration","total_bytes","avg_packet_size","iat_mean"]
    },

    "tcp": {
        "packet_count": (4, 1000),
        "max_packets":1000,

        "packet_size": (40, 1500),

        "flow_duration": (0.01, 120),
        "iat":(0.000001, 2),
        "flow_key": (
            "src_ip", "dst_ip", "src_port", "dst_port", "transport", "protocol"
        ),

        "csv_feature_fields": (
            "src_ip", "dst_ip", "src_port", "dst_port",
            "packet_count", "flow_duration", "avg_packet_size","iat_mean","total_bytes"
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
        },
         "packet_length_bin":[70, 100, 300],
        "iat_bin":[0.0001, 0.01, 0.1,1],
        "evaluation_features":[ "packet_count","flow_duration","total_bytes","avg_packet_size","iat_mean"]
    },
    "http": {
        "packet_count": (4, 1000),
        "max_packets":1000,

        "packet_size": (40, 1500),

        "flow_duration": (0.01, 120),
        "iat":(0.000001, 2),
        "flow_key": (
            "src_ip", "dst_ip", "src_port", "dst_port", "transport", "protocol"
        ),

        "csv_feature_fields": (
            "src_ip", "dst_ip", "src_port", "dst_port",
            "packet_count", "flow_duration", "avg_packet_size","iat_mean","total_bytes"
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
        },
         "packet_length_bin":[70, 100, 300],
        "iat_bin":[0.0001, 0.01, 0.1,1],
        "evaluation_features":[ "packet_count","flow_duration","total_bytes","avg_packet_size","iat_mean"]
    },
    "https": {
        "packet_count": (4, 1000),
        "max_packets":1000,

        "packet_size": (40, 1500),

        "flow_duration": (0.01, 120),
        "iat":(0.000001, 2),
        "flow_key": (
            "src_ip", "dst_ip", "src_port", "dst_port", "transport", "protocol"
        ),

        "csv_feature_fields": (
            "src_ip", "dst_ip", "src_port", "dst_port",
            "packet_count", "flow_duration", "avg_packet_size","iat_mean","total_bytes"
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
        },
         "packet_length_bin":[70, 100, 200],
        "iat_bin":[0.0001, 0.01, 0.1,1],
        "evaluation_features":[ "packet_count","flow_duration","total_bytes","avg_packet_size","iat_mean"]
    },

    "icmp": {
        "packet_count": (2, 20),

        "packet_size": (56, 256),

        "flow_duration": (0.001, 2),
        "iat":(0.000001, 1),
        "flow_key": (
            "protocol","src_ip", "dst_ip", "icmp_id","transport"
        ),

        "csv_feature_fields": (
            "src_ip", "dst_ip", "packet_count", "flow_duration", "avg_packet_size","iat_mean","total_bytes"
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
        },
         "packet_length_bin":[70, 100, 200],
        "iat_bin":[0.0001, 0.01, 0.1],
        "evaluation_features":[ "packet_count","flow_duration","total_bytes","avg_packet_size","iat_mean"]
    },

    "dhcp": {
        "packet_count": (2, 6),

        "packet_size": (300, 600),

        "flow_duration": (0.01, 5),
        "iat":(0.000001, 0.5),
        "flow_key": (
            "protocol",
            "xid"
        ),

        "csv_feature_fields": (
            "xid", "packet_count", "flow_duration", "avg_packet_size","iat_mean","total_bytes"
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
        # "stages":["discover","offer","request","ack"]
        "packet_length_bin":[350, 450, 550],
        "iat_bin":[0.0001, 0.01, 0.1,1],
        "evaluation_features":[ "packet_count","flow_duration","total_bytes","avg_packet_size","iat_mean"]
    },
    "arp": {
        "packet_count": (2, 4),

        "packet_size": (42, 128),

        "flow_duration": (0.0005, 1),
        "iat":(0.000001, 0.5),

        "flow_key": (
            "src_ip",
            "dst_ip",
            "protocol"
        ),

        "csv_feature_fields": (
            "src_ip",
            "dst_ip",
            "packet_count", "flow_duration", "avg_packet_size","iat_mean","total_bytes"
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
        },
        "packet_length_bin":[70, 100, 200],
        "iat_bin":[0.0001, 0.01, 0.1],
        "evaluation_features":[ "packet_count","flow_duration","total_bytes","avg_packet_size","iat_mean"]
    }
}

HTTP = {
    "urls": [
        "/", "/index.html", "/login", "/api/data",
        "/products", "/cart", "/search?q=test"
    ],

    "hosts": [
        "example.com", "google.com", "facebook.com",
        "api.service.com", "myshop.vn"
    ],

    "status_codes": [
        b"200 OK", b"404 Not Found", b"500 Internal Server Error",
        b"301 Moved Permanently"
    ],

    "bodies": [
        b"Hello",
        b"OK",
        b"Success",
        b"Data123",
        b"<html><body>Hi</body></html>"
    ]
}
DNS_DATA = {
    "domains":[
        {
            "domain":"google.com",
            "ips": ["142.250.190.14", "142.250.72.206"]
            },
        {
            "domain":"facebook.com",
            "ips":  ["157.240.22.35", "157.240.1.35"]
            },
        { 
            "domain":"youtube.com",
            "ips":["142.250.72.206", "142.250.190.78"]
            },
        { 
            "domain":"example.com",
            "ips":["93.184.216.34"]
            },
        { 
            "domain":"openai.com",
            "ips":["104.18.12.123", "104.18.13.123"]
            },
        { 
            "domain":"github.com",
            "ips":["140.82.114.4"]
            }
    ]
}
