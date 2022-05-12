#more functions that we might need

def XOR_ENCRYPT3():
    #sample payload
    payload = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    xor_key = "\x58\x58\x11\x62"

    length = len(payload)

    cipher_payload = ""
    for i in range(length):
        t = payload[i]
        k = xor_key[i % len(xor_key)]
        x = ord(k) ^ ord(t)
        ordinal = "%02x" % x
        cipher_payload += ''.join(ordinal)
    print(cipher_payload)

        


#https://github.com/bjornedstrom/elliptic-curve-chemistry-set/blob/master/eddsa.py
def le2int(buf):
    """little endian buffer to integer."""
    integer = 0
    shift = 0
    for byte in buf:
        integer |= ord(byte) << shift
        shift += 8
    return integer

def int2le(integer, pad):
    """integer to little endian buffer."""
    buf = []
    while integer:
        buf.append(chr(integer & 0xff))
        integer >>= 8
        pad -= 1
    while pad > 0:
        buf.append('\x00')
        pad -= 1
    if not buf:
        return '\x00'
    return ''.join(buf)
