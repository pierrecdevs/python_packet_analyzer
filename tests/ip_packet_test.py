
import unittest
import struct
import socket
from net.packets.ip_packet import IPPacket


class TestIPPacket(unittest.TestCase):

    def setUp(self):
        self.packet = IPPacket()

    def test_decode(self):
        # Arrange
        version_ihl = 69  # Version 4 and IHL of 5 (4 << 4 | 5)
        tos = 0
        length = 20 + 12  # Header + payload
        packet_id = 54321
        offset = 0
        ttl = 64
        protocol = 6  # TCP
        checksum = 0
        source_ip = socket.inet_aton('10.13.3.13')
        dest_ip = socket.inet_aton('10.13.3.69')
        payload = b'Hello world!'

        ip_header = struct.pack('!BBHHHBBH4s4s',
                                version_ihl,
                                tos,
                                length,
                                packet_id,
                                offset,
                                ttl,
                                protocol,
                                checksum,
                                source_ip,
                                dest_ip)
        packet_data = ip_header + payload

        # Act
        self.packet.decode(packet_data)

        # Assert
        self.assertEqual(self.packet.version, 4)
        self.assertEqual(self.packet.ihl, 5)
        self.assertEqual(self.packet.tos, tos)
        self.assertEqual(self.packet.length, length)
        self.assertEqual(self.packet.id, packet_id)
        self.assertEqual(self.packet.offset, offset)
        self.assertEqual(self.packet.ttl, ttl)
        self.assertEqual(self.packet.protocol, protocol)
        self.assertEqual(self.packet.source, '10.13.3.13')
        self.assertEqual(self.packet.dest, '10.13.3.69')
        self.assertEqual(self.packet.payload, payload)
        self.assertIs(self.packet.parent, self.packet)

    def test_encode(self):
        # Arrange
        self.packet.version_ihl = 69
        self.packet.tos = 0
        self.packet.length = 32
        self.packet.id = 54321
        self.packet.offset = 0
        self.packet.ttl = 64
        self.packet.protocol = 6
        self.packet.checksum = 0
        self.packet.source = '10.13.3.13'
        self.packet.dest = '10.13.3.69'

        # Act
        encoded = self.packet.encode()
        expected_header = struct.pack('!BBHHHBBH4s4s',
                                      self.packet.version_ihl,
                                      self.packet.tos,
                                      self.packet.length,
                                      self.packet.id,
                                      self.packet.offset,
                                      self.packet.ttl,
                                      self.packet.protocol,
                                      self.packet.checksum,
                                      socket.inet_aton(self.packet.source),
                                      socket.inet_aton(self.packet.dest))

        # Assert
        self.assertEqual(encoded, expected_header)

    def test_get_flags(self):
        # Arrange
        self.packet.offset = 0b0100000000000000  # Don't Fragment

        # Act
        flags = self.packet.get_flags()

        # Assert
        self.assertEqual(flags, '0|1|0')

    def test_get_protocol_name(self):
        # Arrange
        self.packet.protocol = 6
        protocol_name = self.packet.get_protcol_name()
        self.assertEqual(protocol_name, 'TCP')

        # Act
        self.packet.protocol = 999
        protocol_name = self.packet.get_protcol_name()

        # Assert
        self.assertEqual(protocol_name, 'Unknown/Unassigned')

    def test_get_payload(self):
        # Arrange
        self.packet.payload = b'Test payload'

        # Assert
        self.assertEqual(self.packet.get_payload(), b'Test payload')

    def test_get_parent(self):
        # Arrange
        self.packet.parent = self.packet

        # Act
        self.assertIs(self.packet.get_parent(), self.packet)


if __name__ == '__main__':
    unittest.main()
