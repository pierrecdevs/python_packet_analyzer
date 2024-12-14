import unittest
import struct
from net.packets.udp_packet import UDPPacket


class TestUDPPacket(unittest.TestCase):

    def setUp(self):
        self.packet = UDPPacket()

    def test_decode(self):
        # Arrange
        source_port = 12345
        dest_port = 80
        length = 16  # Header (8 bytes) + payload (8 bytes)
        checksum = 4321
        payload = b'Hello UDP!'

        # Act
        udp_header = struct.pack('!HHHH',
                                 source_port,
                                 dest_port,
                                 length,
                                 checksum)
        packet_data = udp_header + payload

        self.packet.decode(packet_data)

        # Assert
        self.assertEqual(self.packet.source_port, source_port)
        self.assertEqual(self.packet.dest_port, dest_port)
        self.assertEqual(self.packet.length, length)
        self.assertEqual(self.packet.checksum, checksum)
        self.assertEqual(self.packet.payload, payload)
        self.assertIs(self.packet.parent, self.packet)

    def test_encode(self):
        # Arrange
        self.packet.source_port = 12345
        self.packet.dest_port = 80
        self.packet.length = 16  # Header (8 bytes) + payload (8 bytes)
        self.packet.checksum = 4321

        # Act
        encoded = self.packet.encode()

        expected_header = struct.pack('!HHHH',
                                      self.packet.source_port,
                                      self.packet.dest_port,
                                      self.packet.length,
                                      self.packet.checksum)

        # Assert
        self.assertEqual(encoded, expected_header)

    def test_get_payload(self):
        # Arrange
        self.packet.payload = b'UDP Payload'

        # Assert
        self.assertEqual(self.packet.get_payload(), b'UDP Payload')

    def test_get_parent(self):
        # Arrange
        self.packet.parent = self.packet

        # Assert
        self.assertIs(self.packet.get_parent(), self.packet)


if __name__ == '__main__':
    unittest.main()
