#!/bin/python3
from argparse import ArgumentParser
from time import time, sleep
from math import floor
from net.sniffer import Sniffer


def main():
    """
    This is an example of sniffing and displaying.
    """
    parser = ArgumentParser(prog='packet_analyzer', description='Simple packet analyzer') 
    parser.add_argument('-i', '--interface', required=True, help='Interface to listen on')
    parser.add_argument('-b', '--buffer-size', type=int,default=65535, help='Max buffer size (default: 65535)')
    parser.add_argument('-w', '--write', help='Write to file (comming soon....)')
    parser.add_argument('-r', '--runtime', type=int, default=0, help='Total run time in second (default: 0 until stopped with ^C)')
    parser.add_argument('-d', '--delay', type=float, default=0.5, help='Delay between reading traffic. (default: 0.5)')
    parser.add_argument('-n', '--number-packets', type=int, default=0, help='Number of packets to sniff')
    args = parser.parse_args()

    s = Sniffer(
            interface=args.interface,
            max_buffer_size=args.buffer_size,
)
    try:

        s.start()

        if args.number_packets > 0:
            for _ in range(args.number_packets):
                for p in s.sniff():
                    s.display_packet(p)
                    sleep(args.delay)
        else:
            start_time = time()
            while args.runtime == 0 or \
                (time() - start_time < floor(int(args.runtime))):
                for p in s.sniff():
                    s.display_packet(p)
                    sleep(args.delay)
        s.stop()
    except StopIteration:
        s.stop()
    except KeyboardInterrupt:
        s.stop()
    finally:
        exit(0)


if __name__ == '__main__':
    main()
