import struct


class UDPPacket(object):
    def __init__(self):
        self.source_port = 0
        self.dest_port = 0
        self.length = 0
        self.checksum = 0
        self.payload = b''
        self.parent = None

    def decode(self, packet):
        udp_header = packet[:8]
        udph = struct.unpack('!HHHH', udp_header)
        self.source_port = udph[0]
        self.dest_port = udph[1]
        self.length = udph[2]
        self.checksum = udph[3]
        self.payload = packet[8:]
        self.parent = self

    def encode(self):
        packet = struct.pack('!HHHH',
                             self.source_port,
                             self.dest_port,
                             self.length,
                             self.checksum)

        return packet

    def get_payload(self):
        return self.payload

    def get_parent(self):
        return self.parent
