#!/usr/bin/env python
import os
import socket
from net.packet_parser import PacketParser

ETHER_P_ALL = 0x0003


class Sniffer(object):

    def __init__(self, interface: str, max_buffer_size: int = 65535):
        self.running = False
        self.max_buffer_size = max_buffer_size
        self.interface = interface
        self.sock = None

    def sniff(self):
        buffer, _ = self.sock.recvfrom(self.max_buffer_size)
        yield buffer

    def start(self, show: bool = False):
        if self.running:
            return

        try:
            if os.name == 'nt':
                socket_protocol = socket.IPPROTO_IP
            else:
                socket_protocol = socket.ntohs(ETHER_P_ALL)

            self.sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket_protocol)

            self.sock.bind((self.interface, 0))

            if os.name == 'nt':
                socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            self.running = True
            if show:
                for packet in self.sniff():
                    self.display_packet(packet)

        except PermissionError:
            print(
                f"[ERROR] Permission error")
            self.running = False
            self.stop()
        except Exception as e:
            print(f"[ERROR] {e}")
            self.running = False
            self.stop()

    def stop(self):
        self.running = False

        if os.name == 'nt':
            socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        if self.sock:
            self.sock.close()
            self.sock = None

    def decode_packet(self, packet):
        return PacketParser.decode(packet)

    def display_packet(self, packet):
        return PacketParser.display_packet(packet)

    def set_max_buffer_size(self, value: int):
        self.max_buffer_size = value
