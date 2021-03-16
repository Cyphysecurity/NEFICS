#!/usr/bin/env python3

from struct import unpack, pack
from scapy.packet import Raw, bind_layers, Padding, Packet, conf
from scapy.layers.inet import TCP, Ether
from scapy.fields import XByteField, ByteField, ShortField, PacketListField, ByteEnumField, PacketField, ConditionalField
from .ioa import IOAS, IOALEN
from .const import TYPE_APCI, SQ, CAUSE_OF_TX, TYPEID_ASDU
from scapy.all import conf

class ASDU(Packet):

    name = 'IEC 60870-5-104-ASDU'
    fields_desc = [
        ByteField('TypeId',None),
        ByteField('SQ',None),
        ByteField('NumIx',0),
        ByteEnumField('CauseTx',None, CAUSE_OF_TX),
        ByteField('Negative',False),
        ByteField('Test', None),
        ByteField('OA',None),
        ByteField('Addr',None),
        PacketListField('IOA', None)
    ]

    def do_dissect(self, s):
        try: # TODO: [Luis] How to use Try & Exception
            self.TypeId = s[0] & 0xff
        except Exception:
            if conf.debug_dissector:
                raise NameError('HiThere')
            self.TypeId = 'Error'
        typeId = s[0] & 0xff
        flags_SQ = s[1] & 0x80
        
        self.SQ =  flags_SQ
        self.NumIx = s[1] & 0x7f
        self.CauseTx = s[2] & 0x3F
        self.Negative = s[2] & 0x40
        self.Test = s[2] & 0x80
        self.OA = s[3]
        self.Addr = unpack('<H',s[4:6])[0]
        # self.Addr = s[4] # NOTE: For Malformed Packets TypeId = 13


        flag=True
        list_IOA = list()
        remain = s[6:]
        # remain = s[5:] # NOTE: For Malformed Packets TypeId = 13 
        
        idx=6
        # idx=5 # NOTE: For Malformed Packets TypeId = 13
        i=1
        typeIOA = IOAS[typeId]
        lenIOA=IOALEN[typeId]
        j=0
        if self.SQ:
            for i in range(1,self.NumIx+1):
                if flag:
                    list_IOA.append(typeIOA(remain[:lenIOA]))
                    offset= list_IOA[0].IOA
                    remain = remain[lenIOA:]
                    idx = idx+lenIOA
                    lenIOA = lenIOA-3
                else:
                    offsetIOA = pack("<H",(i-1)+offset)+b'\x00' # See 7.2.2.1 of IEC 60870-5-101 
                    remain2 = offsetIOA + remain[:lenIOA]
                    list_IOA.append(typeIOA(remain2))
                    remain = remain[lenIOA:]
                    idx = idx+lenIOA
                flag=False
        else:
            for i in range(1,self.NumIx+1):
                list_IOA.append(typeIOA(remain[:lenIOA])) 
                remain = remain[lenIOA:]
                idx= idx+lenIOA
        self.IOA = list_IOA
        return s[idx:]

    def extract_padding(self, s):
        return None, s

    def do_build(self):
        s = list(range(6))
        s[0] = self.TypeId
        s[1] = ((self.SQ << 7) & 0x80) | self.NumIx
        s[2] = self.Test << 7 | self.Negative << 6 | self.CauseTx
        s[3] = self.OA
        s[4] = (self.Addr & 0xff)
        s[5] = ((self.Addr >> 8) & 0xFF)
        if self.IOA is not None:
            for i in self.IOA:
                s += i.do_build()
        
        return bytes(s)

    def __bytes__(self):
        return bytes(self.build())

class APCI(Packet):

    name = 'IEC 60870-5-104-APCI'

    fields_desc = [
        XByteField('START', 0x68),
        ByteField('ApduLen', 4),
        ByteEnumField('Type', 0x00, TYPE_APCI),
        ConditionalField(XByteField('UType', 0x01), lambda pkt: pkt.Type == 0x03),
        ConditionalField(ShortField('Tx', 0x00), lambda pkt: pkt.Type == 0x00),
        ConditionalField(ShortField('Rx', 0x00), lambda pkt: pkt.Type < 3),
    ]

    def do_dissect(self, s):
        self.START = s[0]
        self.ApduLen = s[1]
        self.Type = s[2] & 0x03 if bool(s[2] & 0x01) else 0x00
        if self.Type == 3:
            self.UType = (s[2] & 0xfc) >> 2
        else:
            if self.Type == 0:
                self.Tx = (s[3] << 7) | (s[2] >> 1)
            self.Rx = (s[5] << 7) | (s[4] >> 1)
        return s[6:]

    def dissect(self, s):
        s = self.pre_dissect(s)
        s = self.do_dissect(s)
        s = self.post_dissect(s)
        payl, pad = self.extract_padding(s)
        self.do_dissect_payload(payl)
        if pad and conf.padding:
            self.add_payload(Padding(pad))

    def do_build(self):
        s = list(range(6))
        s[0] = 0x68
        s[1] = self.ApduLen
        if self.Type == 0x03:
            s[2] = ((self.UType << 2) & 0xfc) | self.Type 
            s[3] = 0
            s[4] = 0
            s[5] = 0
        else:
            if self.Type == 0x00:
                s[2] = ((self.Tx << 1) & 0x00fe) | self.Type
                s[3] = ((self.Tx << 1) & 0xff00) >> 8
            else:
                s[2] = self.Type
                s[3] = 0
            s[4] = (self.Rx << 1) & 0x00fe
            s[5] = (self.Rx & 0xff00) >> 8
        return bytes(s)

    def extract_padding(self, s):
        if self.Type == 0x00 and self.ApduLen > 4:
            return s[:self.ApduLen - 4], s[self.ApduLen - 4:]
        return None, s
    
    def do_dissect_payload(self, s):
        if s is not None:
            p = ASDU(s, _internal=1, _underlayer=self)
            self.add_payload(p)

class APDU(Packet):
    name = 'APDU'

    def dissect(self, s):
        s = self.pre_dissect(s)
        s = self.do_dissect(s)
        s = self.post_dissect(s)
        payl, pad = self.extract_padding(s) 
        self.do_dissect_payload(payl)
        if pad and conf.padding:
            if pad[0] in [0x68]: #TODO: [Luis] "self.underlayer is not None"
                self.add_payload(APDU(pad, _internal=1, _underlayer=self))
            else:
                self.add_payload(Padding(pad))
    
    def do_dissect(self, s):
        apci = APCI(s, _internal=1, _underlayer=self)
        self.add_payload(apci)

    def extract_padding(self, s):
        return None, s

bind_layers(TCP, APDU, sport=2404)
bind_layers(TCP, APDU, dport=2404)

if __name__ == '__main__':
    from binascii import hexlify, unhexlify
    print('Dissecting "68040e001e00" ...\r\n')
    data = unhexlify('68040e001e00')
    data2 = unhexlify('00000c9ff00000090f09020708004500003a1dc540003f06337fc0a8fa03c0a86f25cdf40964d5df3c27dab0e477801801f5de5400000101080abca025b50574f04168040100c252')
    APDU(data).show()
    Ether(data2).show()
    print('\r\nBuilding "68040e001e00"...\r\n')
    pkt = APDU()/APCI(ApduLen=4, Type=0x00, Tx=7, Rx=15)
    a = pkt.build()
    pkt.show()
    print('Result:', hexlify(a))
