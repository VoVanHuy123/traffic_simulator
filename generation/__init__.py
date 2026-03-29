from .registry import GeneratorRegistry
from .TCP_generator import TCPFlowGenerator, HTTPFlowGenerator
from .UDP_generator import UDPFlowGenerator, DNSFlowGenerator,DHCPFlowGenerator
from .ICMP_generator import ICMPFlowGenerator
from .ARP_generator import ARPFlowGenerator

GenRegistry = GeneratorRegistry()

GenRegistry.register(TCPFlowGenerator())
GenRegistry.register(HTTPFlowGenerator())
GenRegistry.register(UDPFlowGenerator())
GenRegistry.register(DNSFlowGenerator())
GenRegistry.register(DHCPFlowGenerator())
GenRegistry.register(ICMPFlowGenerator())
GenRegistry.register(ARPFlowGenerator())