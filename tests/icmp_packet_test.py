import unittest
import struct
from net.packets.icmp_packet import ICMPPacket


class TestICMPPacket(unittest.TestCase):

    def setUp(self):
        self.packet = ICMPPacket()

    def test_decode(self):
        # Arrange
        type = 8  # Echo request
        code = 0
        checksum = 0x1a2b
        identifier = 0x1234
        sequence_number = 0x0001
        payload = b"Hello ICMP!"

        # Act
        icmp_header = struct.pack('!BBHHH',
                                  type,
                                  code,
                                  checksum,
                                  identifier,
                                  sequence_number)
        packet_data = icmp_header + payload

        self.packet.decode(packet_data)

        # Assert
        self.assertEqual(self.packet.type, type)
        self.assertEqual(self.packet.code, code)
        self.assertEqual(self.packet.checksum, checksum)
        self.assertEqual(self.packet.identifier, identifier)
        self.assertEqual(self.packet.sequence_number, sequence_number)
        self.assertEqual(self.packet.payload, payload)

    def test_encode(self):
        # Arrange
        self.packet.type = 8
        self.packet.code = 0
        self.packet.checksum = 0x1a2b
        self.packet.identifier = 0x1234
        self.packet.sequence_number = 0x0001
        self.packet.payload = b"Hello ICMP!"

        encoded = self.packet.encode()

        # Act
        expected_header = struct.pack('!BBHHH',
                                      self.packet.type,
                                      self.packet.code,
                                      self.packet.checksum,
                                      self.packet.identifier,
                                      self.packet.sequence_number)
        expected_packet = expected_header + self.packet.payload

        # Assert
        self.assertEqual(encoded, expected_packet)

    def test_get_payload(self):
        # Arrange
        self.packet.payload = b"ICMP Payload"

        # Assert
        self.assertEqual(self.packet.get_payload(), b"ICMP Payload")

    def test_set_payload(self):
        # Arrange
        self.packet.set_payload(b"New Payload")

        # Assert
        self.assertEqual(self.packet.payload, b"New Payload")


if __name__ == '__main__':
    unittest.main()
