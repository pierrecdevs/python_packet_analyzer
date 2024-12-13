import struct
import socket


class IPPacket(object):
    def __init__(self):
        self.version_ihl = 0
        self.version = 0
        self.ihl = 0
        self.tos = 0
        self.length = 0
        self.id = 0
        self.offset = 0
        self.ttl = 0
        self.protocol = 0
        self.checksum = 0
        self.source = 0
        self.dest = 0
        self.payload = 0
        self.parent = None

    def decode(self, packet):
        ip_header = packet[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        self.version_ihl = iph[0]
        self.version = self.version_ihl >> 4
        self.ihl = self.version_ihl & 0xF

        iph_len = self.ihl * 4
        self.tos = iph[1]
        self.length = iph[2]
        self.id = iph[3]
        self.offset = iph[4]
        self.ttl = iph[5]
        self.protocol = iph[6]
        self.checksum = iph[7]
        self.source = socket.inet_ntoa(iph[8])
        self.dest = socket.inet_ntoa(iph[9])
        self.payload = packet[iph_len:]
        self.parent = self

    def encode(self):
        ip_header = struct.pack('!BBHHHBBH4s4s',
                                self.version_ihl,
                                self.tos,
                                self.length,
                                self.id,
                                self.offset,
                                self.ttl,
                                self.protocol,
                                self.checksum,
                                socket.inet_aton(str(self.source)),
                                socket.inet_aton(str(self.dest)),
                                )
        return ip_header

    def get_payload(self):
        return self.payload

    def get_parent(self):
        return self.parent

    def get_flags(self):
        flag_offset = self.offset
        x_bit = (flag_offset >> 15) & 1
        DFF = (flag_offset >> 14) & 1  # Don't Frag
        MFF = (flag_offset >> 13) & 1  # More Frag
        self.offset = str(self.offset & 8191)
        self.flags = f'{str(x_bit)}|{str(DFF)}|{str(MFF)}'

        return self.flags

    def get_protcol_name(self):
        protocol_dict = {
            0: "HOPOPT",
            1: "ICMP",
            2: "IGMP",
            3: "GGP",
            4: "IP-in-IP",
            5: "ST",
            6: "TCP",
            7: "CBT",
            8: "EGP",
            9: "IGP",
            10: "BBN-RCC-MON",
            11: "NVP-II",
            12: "PUP",
            13: "ARGUS",
            14: "EMCON",
            15: "XNET",
            16: "CHAOS",
            17: "UDP",
            18: "MUX",
            19: "DCN-MEAS",
            20: "HMP",
            21: "PRM",
            22: "XNS-IDP",
            23: "TRUNK-1",
            24: "TRUNK-2",
            25: "LEAF-1",
            26: "LEAF-2",
            27: "RDP",
            28: "IRTP",
            29: "ISO-TP4",
            30: "NETBLT",
            31: "MFE-NSP",
            32: "MERIT-INP",
            33: "DCCP",
            34: "3PC",
            35: "IDPR",
            36: "XTP",
            37: "DDP",
            38: "IDPR-CMTP",
            39: "TP++",
            40: "IL",
            41: "IPv6",
            42: "SDRP",
            43: "IPv6-Route",
            44: "IPv6-Frag",
            45: "IDRP",
            46: "RSVP",
            47: "GRE",
            48: "DSR",
            49: "BNA",
            50: "ESP",
            51: "AH",
            52: "I-NLSP",
            53: "SwIPe",
            54: "NARP",
            55: "MOBILE",
            56: "TLSP",
            57: "SKIP",
            58: "IPv6-ICMP",
            59: "IPv6-NoNxt",
            60: "IPv6-Opts",
            61: "Any host internal protocol",
            62: "CFTP",
            63: "Any local network",
            64: "SAT-EXPAK",
            65: "KRYPTOLAN",
            66: "RVD",
            67: "IPPC",
            68: "Any distributed file system",
            69: "SAT-MON",
            70: "VISA",
            71: "IPCU",
            72: "CPNX",
            73: "CPHB",
            74: "WSN",
            75: "PVP",
            76: "BR-SAT-MON",
            77: "SUN-ND",
            78: "WB-MON",
            79: "WB-EXPAK",
            80: "ISO-IP",
            81: "VMTP",
            82: "SECURE-VMTP",
            83: "VINES",
            84: "IPTM",  # Note: 'TTP' has the same number 84 but is obsoleted
            85: "NSFNET-IGP",
            86: "DGP",
            87: "TCF",
            88: "EIGRP",
            89: "OSPF",
            90: "Sprite-RPC",
            91: "LARP",
            92: "MTP",
            93: "AX.25",
            94: "OS",
            95: "MICP",
            96: "SCC-SP",
            97: "ETHERIP",
            98: "ENCAP",
            99: "Any private encryption scheme",
            100: "GMTP",
            101: "IFMP",
            102: "PNNI",
            103: "PIM",
            104: "ARIS",
            105: "SCPS",
            106: "QNX",
            107: "A/N",
            108: "IPComp",
            109: "SNP",
            110: "Compaq-Peer",
            111: "IPX-in-IP",
            112: "VRRP",
            113: "PGM",
            114: "Any 0-hop protocol",
            115: "L2TP",
            116: "DDX",
            117: "IATP",
            118: "STP",
            119: "SRP",
            120: "UTI",
            121: "SMP",
            122: "SM",
            123: "PTP",
            124: "IS-IS over IPv4",
            125: "FIRE",
            126: "CRTP",
            127: "CRUDP",
            128: "SSCOPMCE",
            129: "IPLT",
            130: "SPS",
            131: "PIPE",
            132: "SCTP",
            133: "FC",
            134: "RSVP-E2E-IGNORE",
            135: "Mobility Header",
            136: "UDPLite",
            137: "MPLS-in-IP",
            138: "manet",
            139: "HIP",
            140: "Shim6",
            141: "WESP",
            142: "ROHC",
            143: "Ethernet",
            144: "AGGFRAG",
            145: "NSH",
        }

        try:
            return protocol_dict[self.protocol]
        except Exception:
            return 'Unknown/Unassigned'
