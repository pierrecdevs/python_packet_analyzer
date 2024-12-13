import socket
import struct


class EthernetFrame(object):
    def __init__(self):
        self.ether_type = 0
        self.dest = ''
        self.source = ''
        self.payload = ''
        self.parent = None

    def decode(self, packet):
        ethernet_header = packet[:14]
        eth = struct.unpack('!6s6sH', ethernet_header)

        self.ether_type = socket.htons(eth[2])
        self.dest = self.get_ethernet_addr(packet[0:6])
        self.source = self.get_ethernet_addr(packet[6:12])
        self.payload = packet[14:]
        self.parent = self

    def encode(self):
        eth = struct.pack('!6s6sH', self.dest, self.source, self.ether_type)
        return eth

    def get_ethernet_addr(self, addr: str) -> str:
        ether_addr = ":".join(map("{:02x}".format, addr))

        return ether_addr

    def get_payload(self):
        return self.payload

    def get_parent(self):
        return self.parent
