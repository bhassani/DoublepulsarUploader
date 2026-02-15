#original source: https://github.com/SecureAuthCorp/impacket/blob/master/impacket/nmb.py

# NetBIOS Session Types
NETBIOS_SESSION_MESSAGE = 0x0

class NetBIOSSessionPacket:
    def __init__(self, data=0):
        self.type = 0x0
        self.flags = 0x0
        self.length = 0x0
        if data == 0:
            self._trailer = b''
        else:
            try:
                self.type = indexbytes(data,0)
                if self.type == NETBIOS_SESSION_MESSAGE:
                    self.length = indexbytes(data,1) << 16 | (unpack('!H', data[2:4])[0])
                else:
                    self.flags = data[1]
                    self.length = unpack('!H', data[2:4])[0]

                self._trailer = data[4:]
            except:
                raise NetBIOSError('Wrong packet format ')

     def set_type(self, type):
        self.type = type
        
     def set_trailer(self, data):
        self._trailer = data
        self.length = len(data)   
                           
def send_packet(self, data):
    p = NetBIOSSessionPacket()
    p.set_type(NETBIOS_SESSION_MESSAGE)
    p.set_trailer(data)
    self._sock.sendall(p.rawData())

# Represents a SMB Packet
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

class SMBTransaction2_Parameters(SMBCommand_Parameters):
structure = (
        ('TotalParameterCount','<H'),
        ('TotalDataCount','<H'),
        ('MaxParameterCount','<H=1024'),
        ('MaxDataCount','<H=65504'),
        ('MaxSetupCount','<B=0'),
        ('Reserved1','<B=0'),
        ('Flags','<H=0'),
        ('Timeout','<L=0'),
        ('Reserved2','<H=0'),
        ('ParameterCount','<H'),
        ('ParameterOffset','<H'),
        ('DataCount','<H'),
        ('DataOffset','<H'),
        ('SetupCount','<B=len(Setup)//2'),
        ('Reserved3','<B=0'),
        ('SetupLength','_-Setup','SetupCount*2'),
        ('Setup',':'),
)

class SMBTransaction2_Data(Structure):
structure = (
#       ('NameLength','_-Name','1'),
#       ('Name',':'),
        ('Pad1Length','_-Pad1','self["Pad1Length"]'),
        ('Pad1',':'),
        ('Trans_ParametersLength','_-Trans_Parameters','self["Trans_ParametersLength"]'),
        ('Trans_Parameters',':'),
        ('Pad2Length','_-Pad2','self["Pad2Length"]'),
        ('Pad2',':'),
        ('Trans_DataLength','_-Trans_Data','self["Trans_DataLength"]'),
        ('Trans_Data',':'),
)

def sendSMB(self,smb):
    smb['Uid'] = self._uid
    #At least on AIX, PIDs can exceed 16 bits, so we mask them out
    smb['Pid'] = (os.getpid() & 0xFFFF)
    # set flags
    smb['Flags1'] |= self.__flags1
    smb['Flags2'] |= self.__flags2
    if self._SignatureEnabled:
        smb['Flags2'] |= SMB.FLAGS2_SMB_SECURITY_SIGNATURE
        self.signSMB(smb, self._SigningSessionKey, self._SigningChallengeResponse)

    self._sess.send_packet(smb.getData())

def send_trans2(self, tid, setup, name, param, data):
        smb = NewSMBPacket()
        smb['Tid']    = tid

        command = pack('<H', setup)

        transCommand = SMBCommand(SMB.SMB_COM_TRANSACTION2)
        transCommand['Parameters'] = SMBTransaction2_Parameters()
        transCommand['Parameters']['MaxDataCount'] = self._dialects_parameters['MaxBufferSize']
        transCommand['Data'] = SMBTransaction2_Data()

        transCommand['Parameters']['Setup'] = command
        transCommand['Parameters']['TotalParameterCount'] = len(param)
        transCommand['Parameters']['TotalDataCount'] = len(data)

        if len(param) > 0:
            padLen = (4 - (32+2+28 + len(command)) % 4 ) % 4
            padBytes = '\xFF' * padLen
            transCommand['Data']['Pad1'] = padBytes
        else:
            transCommand['Data']['Pad1'] = ''
            padLen = 0

        transCommand['Parameters']['ParameterCount'] = len(param)
        transCommand['Parameters']['ParameterOffset'] = 32+2+28+len(command)+len(name) + padLen

        if len(data) > 0:
            pad2Len = (4 - (32+2+28 + len(command) + padLen + len(param)) % 4) % 4
            transCommand['Data']['Pad2'] = '\xFF' * pad2Len
        else:
            transCommand['Data']['Pad2'] = ''
            pad2Len = 0

        transCommand['Parameters']['DataCount'] = len(data)
        transCommand['Parameters']['DataOffset'] = transCommand['Parameters']['ParameterOffset'] + len(param) + pad2Len

        transCommand['Data']['Name'] = name
        transCommand['Data']['Trans_Parameters'] = param
        transCommand['Data']['Trans_Data'] = data
        smb.addCommand(transCommand)

        self.sendSMB(smb)
