#!/bin/python3
from net.sniffer import Sniffer


def main():
    s = Sniffer('eth0')
    try:
        s.start()
    except KeyboardInterrupt:
        s.stop()


if __name__ == '__main__':
    main()
