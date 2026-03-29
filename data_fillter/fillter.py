# import scapy
from scapy.all import rdpcap,wrpcap,Ether, IP, TCP, UDP, ICMP, PcapReader, PcapWriter
import pyshark
import subprocess
import re

 

class PcapFillter:
    def __init__(self):
        pass
    def filter_packets_pcap(self,
        input_pcap,
        output_pcap,
        protocol=None,
        src_ip=None,
        dst_ip=None,
        src_port=None,
        dst_port=None,
        limit_packets=None
    ):

        filters = []

        # protocol filter
        if protocol:
            filters.append(protocol.lower())

        # IP filter
        if src_ip:
            filters.append(f"ip.src == {src_ip}")

        if dst_ip:
            filters.append(f"ip.dst == {dst_ip}")

        # port filter
        port_filter = []

        if src_port:
            port_filter.append(f"tcp.srcport == {src_port} || udp.srcport == {src_port}")

        if dst_port:
            port_filter.append(f"tcp.dstport == {dst_port} || udp.dstport == {dst_port}")

        if port_filter:
            filters.append("(" + " || ".join(port_filter) + ")")

        display_filter = " && ".join(filters)

        print("Display filter:", display_filter)

        cmd = ["tshark", "-r", input_pcap]

        if display_filter:
            cmd += ["-Y", display_filter]

        # packet limit
        if limit_packets:
            cmd += ["-c", str(limit_packets)]

        cmd += ["-w", output_pcap]

        subprocess.run(cmd)


    def count_packets(self,pcap_file):
        cmd = ["capinfos", pcap_file]

        result = subprocess.run(cmd, capture_output=True, text=True)

        match = re.search(r"Number of packets:\s+(\d+)", result.stdout)

        if match:
            return int(match.group(1))
        else:
            raise Exception("Cannot detect packet count")


    def split_pcap(self,input_pcap, output_prefix, ratio):

        total = self.count_packets(input_pcap)

        target = int(total * ratio)

        print("Total packets:", total)
        print("Extract packets:", target)

        self.filter_packets_pcap(input_pcap, f"{output_prefix}.pcap", limit_packets=target)


if __name__ == "__main__":
    protocol = "dhcp"
    raw_packet_path = "data/my_com_dhcp.pcapng"
    # raw_packet_path = "raw_data/Friday-WorkingHours.pcap"
    output_pcap = f"data/dhcp/{protocol}1_pcap.pcap" 
    fillter = PcapFillter()
    fillter.filter_packets_pcap(raw_packet_path, output_pcap, protocol="dhcp")
    