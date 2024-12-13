def get_xbit(n, k):
    return (n & (1 << k)) >> k


def calculate_checksum(value):
    checkSum = 0
    for i in range(0, len(value), 2):
        checkSum += (ord(value[i]) << 8) + (ord(value[i + 1]))
    return ~((checkSum >> 16) + (checkSum & 0xffff)) & 0xffff
