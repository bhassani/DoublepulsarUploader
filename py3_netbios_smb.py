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
