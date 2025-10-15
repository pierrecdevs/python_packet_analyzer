#!/usr/bin/env python
from typing import Any, Dict

from net.packets.ethernet_frame import EthernetFrame
from net.packets.ip_packet import IPPacket
from net.packets.icmp_packet import ICMPPacket
from net.packets.udp_packet import UDPPacket
from net.packets.tcp_packet import TCPPacket


class PacketParser(object):
    def __init__(self):
        pass

    @staticmethod
    def decode(buffer: bytes) -> Any:
        try:
            packet: bytes = buffer
            result: Dict[str, Any] = {}
            ethernet = EthernetFrame()
            ethernet.decode(packet)
            result.update({'Ethernet': ethernet})

            if ethernet.ether_type == 8:
                ip = IPPacket()
                ip.decode(ethernet.payload)
                result.update({'IP': ip})

                if ip.protocol == 1:
                    print('\t\t [ICMP Packet]')
                    icmp = ICMPPacket()
                    icmp.decode(ethernet.payload)
                    result.update({'ICMP': icmp})
                elif ip.protocol == 6:
                    tcp = TCPPacket()
                    tcp.decode(ip.payload)
                    result.update({'TCP': tcp})
                elif ip.protocol == 17:
                    print('\t\t [UDP Packet]')
                    udp = UDPPacket()
                    udp.decode(ip.payload)
                    result.update({'UDP': udp})
                else:
                    result.update({'OTHER': ip.protocol})
                return result
        except Exception as ex:
            return ex

    @staticmethod
    def display_packet(packet):
        ethernet = EthernetFrame()
        ethernet.decode(packet)

        print('[Ethernet Frame]')
        print(
            f'  Source MAC: {ethernet.source}, Dest MAC: {ethernet.dest}, Protocol: {ethernet.ether_type}')

        if ethernet.ether_type == 8:
            ip = IPPacket()
            ip.decode(ethernet.payload)
            print('\t [IP Packet]')
            print(
                f'\t  Version: {ip.version}, Header Length: {ip.ihl}, TOS: {ip.tos}, Total Length: {ip.length}')
            print(
                f'\t  ID: {ip.id}, Flags: {ip.get_flags()}, Frag Offset: {ip.offset}, TTL: {ip.ttl}')
            print(
                f'\t  Protocol: {ip.protocol}, Checksum: {ip.checksum}, IP Source: {ip.source}, IP Dest: {ip.dest}')

            if ip.protocol == 1:
                print('\t\t [ICMP Packet]')
                icmp = ICMPPacket()
                icmp.decode(ethernet.payload)
                print(
                    f'\t\t  Type: {icmp.type} Code: {icmp.code} Id: {icmp.identifier} Sequence: {icmp.sequence_number}')
                print(f'\t\t  [Data]\n\t\t {icmp.payload}')
            elif ip.protocol == 6:
                tcp = TCPPacket()
                tcp.decode(ip.payload)
                print('\t\t [TCP Packet]')
                print(
                    f'\t\t    Source Port: {tcp.source_port}, Dest Port: {tcp.dest_port}, Sequence: {tcp.sequence_number} ACK No: {tcp.ack_sequence}')
                print(
                    f'\t\t    Flags: {tcp.urg_bit}|{tcp.ack_bit}|{tcp.psh_bit}|{tcp.rst_bit}|{tcp.syn_bit}|{tcp.fin_bit}')
                print(
                    f'\t\t    Window: {tcp.window}, Checksum: {tcp.checksum}, URG Ptr: {tcp.urg}')
                print(f'\t\t    [Data]\n\t\t  {tcp.get_payload()}')
                print(f'\t\t ')
            elif ip.protocol == 17:
                print('\t\t [UDP Packet]')
                udp = UDPPacket()
                udp.decode(ip.payload)
                print(
                    f'\t\t    Source Port: {udp.source_port}, Dest Port: {udp.dest_port}')
                print(f'\t\t    [Data]\n\t\t {udp.get_payload()}')
            else:
                print(f'\t\t\t    [Protocol: {ip.protocol}]')
