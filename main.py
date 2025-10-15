#!/bin/python3
from argparse import ArgumentParser
from net.sniffer import Sniffer


def main():
    parser = ArgumentParser(prog='packet_analyzer', description='Simple packet analyzer') 
    parser.add_argument('-i', '--interface', required=True, help='Interface to listen on')
    parser.add_argument('-b', '--buffer-size', type=int,default=65535, help='Max buffer size (default: 65535)')
    parser.add_argument('-w', '--write', help='Write to file (comming soon....)')
    args = parser.parse_args()

    s = Sniffer(args.interface, args.buffer_size)
    try:
        s.start()
    except KeyboardInterrupt:
        s.stop()


if __name__ == '__main__':
    main()
