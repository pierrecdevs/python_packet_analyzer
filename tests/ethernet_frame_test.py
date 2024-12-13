import unittest
import struct
import socket
from net.packets.ethernet_frame import EthernetFrame


class TestEthernetFrame(unittest.TestCase):

    def setUp(self):
        self.frame = EthernetFrame()

    def test_decode(self):
        # Arrange
        dest = b'\xaa\xbb\xcc\xdd\xee\xff'
        source = b'\x11\x22\x33\x44\x55\x66'
        ether_type = 0x0800
        payload = b'hello world'
        packet = struct.pack('!6s6sH', dest, source, ether_type) + payload

        # Act
        self.frame.decode(packet)

        # Assert
        self.assertEqual(self.frame.dest, 'aa:bb:cc:dd:ee:ff')
        self.assertEqual(self.frame.source, '11:22:33:44:55:66')
        self.assertEqual(self.frame.ether_type, socket.htons(0x0800))
        self.assertEqual(self.frame.payload, payload)
        self.assertIs(self.frame.parent, self.frame)

    def test_encode(self):
        # Arrange
        self.frame.dest = b'\xaa\xbb\xcc\xdd\xee\xff'
        self.frame.source = b'\x11\x22\x33\x44\x55\x66'
        self.frame.ether_type = 0x0800

        # Act
        encoded_frame = self.frame.encode()
        expected_frame = struct.pack(
            '!6s6sH', self.frame.dest, self.frame.source, self.frame.ether_type)

        # Assert
        self.assertEqual(encoded_frame, expected_frame)

    def test_get_ethernet_addr(self):
        # Arrange
        addr = b'\xaa\xbb\xcc\xdd\xee\xff'

        # Act
        result = self.frame.get_ethernet_addr(addr)

        # Assert
        self.assertEqual(result, 'aa:bb:cc:dd:ee:ff')

    def test_get_payload(self):
        # Arrange
        self.frame.payload = b'hello world'

        # Act
        result = self.frame.get_payload()

        # Assert
        self.assertEqual(result, b'hello world')

    def test_get_parent(self):
        # Arrange
        self.frame.parent = self.frame

        # Act
        result = self.frame.get_parent()

        # Assert
        self.assertIs(result, self.frame)


if __name__ == '__main__':
    unittest.main()
