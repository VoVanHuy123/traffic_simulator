from .registry import GeneratorRegistry
from .TCP_generator import TCPFlowGenerator, HTTPFlowGenerator
from .UDP_generator import UDPFlowGenerator, DNSFlowGenerator, DHCPFlowGenerator
from .ICMP_generator import ICMPFlowGenerator
from .ARP_generator import ARPFlowGenerator
from .ISUP_generator import ISUPFlowGenerator
from .SIP_generator import SIPFlowGenerator
from .RADIUS_generator import RADIUSFlowGenerator
from .GTP_generator import GTPFlowGenerator
from .RTP_generator import RTPFlowGenerator
from .MAP_generator import MAPFlowGenerator
from .Diameter_generator import DiameterFlowGenerator

GenRegistry = GeneratorRegistry()

GenRegistry.register(TCPFlowGenerator())
GenRegistry.register(HTTPFlowGenerator())
GenRegistry.register(UDPFlowGenerator())
GenRegistry.register(DNSFlowGenerator())
GenRegistry.register(DHCPFlowGenerator())
GenRegistry.register(ICMPFlowGenerator())
GenRegistry.register(ARPFlowGenerator())
GenRegistry.register(ISUPFlowGenerator())
GenRegistry.register(SIPFlowGenerator())
GenRegistry.register(RADIUSFlowGenerator())
GenRegistry.register(GTPFlowGenerator())
GenRegistry.register(RTPFlowGenerator())
GenRegistry.register(MAPFlowGenerator())
GenRegistry.register(DiameterFlowGenerator())