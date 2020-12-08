#!/usr/bin/env python3

import struct
from scapy.config import conf
from scapy.packet import Packet
from scapy.fields import Field, StrField, XByteField, ByteField, PacketField

class LEFloatField(Field):
    '''
    little-endian float
    '''
    def __init__(self, name, default):
        Field.__init__(self, name, default, '<f')

class SignedShortField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<h")

class IOAID(Field):

    def __init__(self, name, default):
        Field.__init__(self, name, default, '<I')

    def addfield(self, pkt, s, val):
        if val is None:
            return s
        value = []
        value.append(int(val & 0xff))
        value.append(int((val & 0xff00) / 0x0100))
        value.append(int((val & 0xff0000) / 0x010000))
        # return s + struct.pack('BBB', value[0], value[1], value[2])
        return s + struct.pack('BB', value[0], value[1])
 

    def getfield(self, pkt, s):
        # return s[3:], self.m2i(pkt, struct.unpack(self.fmt, s[:3] + b'\x00')[0])
        return s[2:], self.m2i(pkt, struct.unpack(self.fmt, s[:2] + b'\x00\x00')[0]) # NOTE: For INFORMATION OBJECT ADDRESS of two octets