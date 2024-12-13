import struct


class ICMPPacket:
    def __init__(self):
        self.type = 0
        self.code = 0
        self.checksum = 0
        self.identifier = 0
        self.sequence_number = 0
        self.payload = b''

    def decode(self, packet):
        icmp_header = packet[:8]
        icmph = struct.unpack('!BBHHH', icmp_header)
        self.type = icmph[0]
        self.code = icmph[1]
        self.checksum = icmph[2]
        self.identifier = icmph[3]
        self.sequence_number = icmph[4]
        self.payload = packet[8:]

    def encode(self):
        packet = struct.pack('!BBHHH',
                             self.type,
                             self.code,
                             self.checksum,
                             self.identifier,
                             self.sequence_number)
        return packet + self.payload

    def get_payload(self):
        return self.payload

    def set_payload(self, payload):
        self.payload = payload
