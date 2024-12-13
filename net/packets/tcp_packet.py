import struct
from helpers import get_xbit


class TCPPacket(object):
    def __init__(self):
        self.source_port = 0
        self.dest_port = 0
        self.sequence_number = 0
        self.ack_sequence = 0
        self.data_offset = 0
        self.flags = 0
        self.fin_bit = 0
        self.syn_bit = 0
        self.rst_bit = 0
        self.psh_bit = 0
        self.ack_bit = 0
        self.urg_bit = 0
        self.window = 0
        self.checksum = 0
        self.urg = 0
        self.payload = b''
        self.parent = None

    def decode(self, packet):
        tcp_header = packet[0:20]
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)

        self.source_port = tcph[0]
        self.dest_port = tcph[1]
        self.sequence_number = tcph[2]
        self.ack_sequence = tcph[3]
        self.data_offset = tcph[4]
        self.flags = tcph[5]
        self.fin_bit = get_xbit(self.flags, 0)
        self.syn_bit = get_xbit(self.flags, 1)
        self.rst_bit = get_xbit(self.flags, 2)
        self.psh_bit = get_xbit(self.flags, 3)
        self.ack_bit = get_xbit(self.flags, 4)
        self.urg_bit = get_xbit(self.flags, 5)

        tcp_length = self.data_offset >> 4
        self.window = tcph[6]
        self.checksum = tcph[7]
        self.urg = tcph[8]
        self.payload = packet[20:]
        self.parent = self

    def encode(self):
        tcp_header = struct.pack('!HHLLBBHHH',
                                 self.source_port,
                                 self.dest_port,
                                 self.sequence_number,
                                 self.ack_sequence,
                                 self.data_offset,
                                 self.flags,
                                 self.window,
                                 self.checksum,
                                 self.urg,
                                 )
        return tcp_header

    def get_payload(self):
        return self.payload

    def get_parent(self):
        return self.parent
