import binascii

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
  
if __name__ == "__main__":

