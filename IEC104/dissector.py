#!/usr/bin/env python3

from struct import unpack, pack
from scapy.packet import Raw, bind_layers, Padding, Packet, conf
from scapy.layers.inet import TCP, IP, Ether
from scapy.fields import XByteField, ByteField, LEShortField, ShortField, PacketListField, ByteEnumField, PacketField, ConditionalField
from .ioa import IOAS, IOALEN
from .const import TYPE_APCI, SQ_ENUM, CAUSE_OF_TX, PN_ENUM, TYPEID_ASDU
from scapy.all import conf
# import logging

# LOG_FORMAT = '%(asctime)s:%(levelname)s:%(message)s'
# logging.basicConfig(
#     filename= 'logfile.log',
#     level= logging.DEBUG,
#     format= LOG_FORMAT, 
#     filemode= 'w',
# )
# logger = logging.getLogger()

class ASDU(Packet):

    name = 'IEC 60870-5-104-ASDU'
    fields_desc = [
        ByteEnumField('TypeId', None, TYPEID_ASDU),
        ByteEnumField('SQ', None, SQ_ENUM),
        ByteField('NumIx',0),
        ByteEnumField('CauseTx',None, CAUSE_OF_TX),
        ByteEnumField('PN', 0x00, PN_ENUM),
        ByteField('Test', None),
        ByteField('OA',None),
        LEShortField('Addr',None),
        PacketListField('IOA', None)
    ]

    def do_dissect(self, s):
        self.TypeId = s[0]
        self.SQ =  s[1] & 0x80
        self.NumIx = s[1] & 0x7f
        self.CauseTx = s[2] & 0x3F
        self.PN = s[2] & 0x40
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
        typeIOA = IOAS[self.TypeId]
        lenIOA=IOALEN[self.TypeId]
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
            list_IOA = [typeIOA(remain[(x*lenIOA):(x*lenIOA)+lenIOA]) for x in range(self.NumIx)]
            idx += lenIOA * self.NumIx
            # for i in range(1,self.NumIx+1):
            #     list_IOA.append(typeIOA(remain[:lenIOA])) 
            #     remain = remain[lenIOA:]
            #     idx = idx+lenIOA
        self.IOA = list_IOA
        return s[idx:]

    def do_build(self):
        s = bytearray()
        s.append(self.TypeId)
        s.append(self.SQ | self.NumIx)
        s.append(self.Test | self.PN | self.CauseTx)
        s.append(self.OA)
        s.append(int(self.Addr) & 0xff)
        s.append(int(self.Addr) >> 8)
        s = bytes(s)
        if self.IOA is not None:
            for i in self.IOA:
                s += i.build()
        
        return s

class APCI(Packet):

    name = 'IEC 60870-5-104-APCI'

    fields_desc = [
        XByteField('START', 0x68),
        ByteField('ApduLen', 4),
        ByteEnumField('Type', 0x00, TYPE_APCI),
        ConditionalField(XByteField('UType', None), lambda pkt: pkt.Type == 0x03),
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
            s[5] = ((self.Rx << 1) & 0xff00) >> 8
        s = bytes(s)
        if self.haslayer('ASDU'):
            s += self.payload.build()
        return s

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

    # def extract_padding(self, s):
    #     # logger.info("pkt size = {0}".format(len(s)))
    #     print("pkt size = {0}".format(len(s)))
    #     return "", s

    def dissect(self, s):
        s = self.pre_dissect(s)
        s = self.do_dissect(s)
        s = self.post_dissect(s)
        payl, pad = self.extract_padding(s) 
        self.do_dissect_payload(payl)
        if pad and conf.padding:
            if pad[0] in [0x68]: 
                self.add_payload(APDU(pad, _internal=1, _underlayer=self))
            else:
                self.add_payload(Padding(pad))
    
    def do_dissect(self, s):
        apci = APCI(s, _internal=1, _underlayer=self)
        self.add_payload(apci)

bind_layers(TCP, APDU, sport=2404)
bind_layers(TCP, APDU, dport=2404)

if __name__ == '__main__':
    from binascii import hexlify, unhexlify
    from datetime import datetime
    from .ioa import CP56Time
    
    ct = datetime.now()
    ct = CP56Time(MS=ct.second*1000+(ct.microsecond//1000), Min=ct.minute, IV=0, Hour=ct.hour, SU=0, Day=ct.day, DOW=ct.today().weekday()+1, Month=ct.month, Year=ct.year-2000)
    print('Dissecting "00000c9ff00000090f09020708004500003a1dc540003f06337fc0a8fa03c0a86f25cdf40964d5df3c27dab0e477801801f5de5400000101080abca025b50574f04168040100c252" ...\r\n')
    data = unhexlify('00000c9ff00000090f09020708004500003a1dc540003f06337fc0a8fa03c0a86f25cdf40964d5df3c27dab0e477801801f5de5400000101080abca025b50574f04168040100c252')
    Ether(data).show()
    print('\r\nBuilding "00000c9ff00000090f09020708004500003a1dc540003f06337fc0a8fa03c0a86f25cdf40964d5df3c27dab0e477801801f5de5400000101080abca025b50574f04168040100c252"...\r\n')
    pkt = Ether(type=0x0800, src='00:09:0f:09:02:07', dst='00:00:0c:9f:f0:00')/IP(version=4, ihl=5, tos=0x0, len=58, id=7621, flags='DF', frag=0, ttl=63, proto='tcp', src='192.168.250.3', dst='192.168.111.37')/TCP(sport=52724, dport=2404, seq=2577176935, ack=3669025911, dataofs=8, reserved=0, flags='PA', window=501, urgptr=0, options=[('NOP', None), ('NOP', None), ('Timestamp', (3164612021, 91549761))])/APDU()/APCI(ApduLen=4, Type=0x01, Rx=10593)
    a = pkt.build()
    pkt.show()
    print('Result:', hexlify(a))

    pkt = APDU()
    pkt /= APCI(ApduLen=25, Type=0x00, Tx=23, Rx=44)
    pkt /= ASDU(TypeId=36, SQ=0, NumIx=1, CauseTx=1, Test=0, OA=1, Addr=2, IOA=[IOAS[36](IOA=1001, Value=2.3414123, QDS=0x81, CP56Time=ct)])
    pkt.show()
    print('Result:', hexlify(pkt.build()))
