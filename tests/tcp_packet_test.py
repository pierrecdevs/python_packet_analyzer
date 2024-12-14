import unittest
import struct
from net.packets.tcp_packet import TCPPacket
from helpers import get_xbit


class TestTCPPacket(unittest.TestCase):

    def setUp(self):
        self.packet = TCPPacket()

    def test_decode(self):
        # Arrange
        source_port = 12345
        dest_port = 80
        sequence_number = 1000
        ack_sequence = 2000
        data_offset = (5 << 4)  # Data offset (5 words -> 20 bytes)
        flags = 0b000101010  # URG, ACK, PSH bits
        window = 4096
        checksum = 1234
        urg = 0
        payload = b"Hello TCP!"

        tcp_header = struct.pack('!HHLLBBHHH',
                                 source_port,
                                 dest_port,
                                 sequence_number,
                                 ack_sequence,
                                 data_offset,
                                 flags,
                                 window,
                                 checksum,
                                 urg)
        packet_data = tcp_header + payload

        # Act
        self.packet.decode(packet_data)

        # Assert
        self.assertEqual(self.packet.source_port, source_port)
        self.assertEqual(self.packet.dest_port, dest_port)
        self.assertEqual(self.packet.sequence_number, sequence_number)
        self.assertEqual(self.packet.ack_sequence, ack_sequence)
        self.assertEqual(self.packet.data_offset, data_offset)
        self.assertEqual(self.packet.flags, flags)
        self.assertEqual(self.packet.fin_bit, get_xbit(flags, 0))
        self.assertEqual(self.packet.syn_bit, get_xbit(flags, 1))
        self.assertEqual(self.packet.rst_bit, get_xbit(flags, 2))
        self.assertEqual(self.packet.psh_bit, get_xbit(flags, 3))
        self.assertEqual(self.packet.ack_bit, get_xbit(flags, 4))
        self.assertEqual(self.packet.urg_bit, get_xbit(flags, 5))
        self.assertEqual(self.packet.window, window)
        self.assertEqual(self.packet.checksum, checksum)
        self.assertEqual(self.packet.urg, urg)
        self.assertEqual(self.packet.payload, payload)
        self.assertIs(self.packet.parent, self.packet)

    def test_encode(self):
        # Arrange
        self.packet.source_port = 12345
        self.packet.dest_port = 80
        self.packet.sequence_number = 1000
        self.packet.ack_sequence = 2000
        self.packet.data_offset = (5 << 4)
        self.packet.flags = 0b000101010
        self.packet.window = 4096
        self.packet.checksum = 1234
        self.packet.urg = 0

        encoded = self.packet.encode()

        # Act
        expected_header = struct.pack('!HHLLBBHHH',
                                      self.packet.source_port,
                                      self.packet.dest_port,
                                      self.packet.sequence_number,
                                      self.packet.ack_sequence,
                                      self.packet.data_offset,
                                      self.packet.flags,
                                      self.packet.window,
                                      self.packet.checksum,
                                      self.packet.urg)

        # Assert
        self.assertEqual(encoded, expected_header)

    def test_get_payload(self):
        # Arrange
        self.packet.payload = b'TCP Payload'

        # Assert
        self.assertEqual(self.packet.get_payload(), b'TCP Payload')

    def test_get_parent(self):
        # Arrange
        self.packet.parent = self.packet

        # Assert
        self.assertIs(self.packet.get_parent(), self.packet)


if __name__ == '__main__':
    unittest.main()
