from .registry import ProtocolRegistry
from .protocols.dhcp import DHCPHandler
from .protocols.dns import DNSHandler
from .protocols.tcp import TCPHandler,HTTPHandler
from .protocols.imcp import ICMPHandler
from .protocols.arp import ARPHandler
from .protocols.isup import ISUPHandler

ExtractRegistry = ProtocolRegistry()

ExtractRegistry.register(DHCPHandler())
ExtractRegistry.register(DNSHandler())
ExtractRegistry.register(HTTPHandler())
ExtractRegistry.register(ICMPHandler())
ExtractRegistry.register(ARPHandler())
ExtractRegistry.register(ISUPHandler())