PROTOCOL_RULES = {
    "dns": {
        "packet_count": (2,4),
        "packet_size": (60,300),
        "flow_duration": (0.001,0.2)
    },
    "http": {
        "packet_count": (3,300),
        "packet_size": (100,1200),
        "flow_duration": (0.01,100)
    },
    "icmp": {
        "packet_count": (1,5),
        "packet_size": (60,200),
        "flow_duration": (0.001,1)
    }
}