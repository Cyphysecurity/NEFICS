#!/usr/bin/env python3

from nefics.IEC104.dissector import ASDU, APCI, APDU
from nefics.IEC104.ioa import *
import time
from datetime import datetime

APDULEN = {
    3: 14,
    36: 25,
    45: 14,
    50: 18,
}

def cp56time() -> CP56Time:
    now = datetime.now()
    ms = now.second*1000 + int(now.microsecond/1000)
    minu = now.minute
    iv = 0
    hour = now.hour
    su = 0
    day = now.day
    dow = now.today().weekday() + 1
    month = now.month
    year = now.year - 2000
    output = CP56Time(MS = ms, Min = minu, IV = iv, Hour = hour, SU = su, Day = day, DOW = dow, Month = month, Year = year)
    return output

def build_104_asdu_packet(typeASDU: int, asdu:int, ioa: int, tx: int, rx: int, causeTx:int =1, **kwargs) -> bytes: 
    pkt = APDU()
    pkt /= APCI(ApduLen=APDULEN[typeASDU], Type=0x00, Tx=tx, Rx=rx)
    if typeASDU == 3:
        pkt /= ASDU(TypeId=typeASDU, SQ=0, NumIx=1, CauseTx=causeTx, Test=0, OA=0, Addr=asdu, IOA=[IOA3(IOA=ioa, DIQ=DIQ(DPI=kwargs['value'], flags=0))])
    elif typeASDU == 36:
        ct = cp56time()
        pkt /= ASDU(TypeId=typeASDU, SQ=0, NumIx=1, CauseTx=causeTx, Test=0, OA=0, Addr=asdu, IOA=[IOA36(IOA=ioa, Value=kwargs['value'], QDS=0x00, CP56Time=ct)])
    elif typeASDU == 45:
        pkt /= ASDU(TypeId=typeASDU, SQ=0, NumIx=1, CauseTx=causeTx, Test=0, OA=0, Addr=asdu, IOA=[IOA45(IOA=ioa, SCO=SCO(SE=kwargs['SE'], QU=kwargs['QU'], SCS=kwargs['SCS']))])
    elif typeASDU == 50:
        pkt /= ASDU(TypeId=typeASDU, SQ=0, NumIx=1, CauseTx=causeTx, Test=0, OA=0, Addr=asdu, IOA=[IOA50(IOA=ioa, Value=kwargs['value'], QOS=QOS(QL=0, SE=0))])
    else:
        raise AttributeError
    if __name__ == '__main__':
        pkt.show()
    return pkt.build()

def extract_104_value(pkt: APDU) -> dict:
    if pkt.haslayer('IOA3'):
        ioa = pkt['IOA3'].IOA
        value = pkt['DIQ'].DPI
    elif pkt.haslayer('IOA36'):
        ioa = pkt['IOA36'].IOA
        value = pkt['IOA36'].Value
    elif pkt.haslayer('IOA45'):
        ioa = pkt['IOA45'].IOA
        value = pkt['IOA45'].SCO.SE | pkt['IOA45'].SCO.SCS
    elif pkt.haslayer('IOA50'):
        ioa = pkt['IOA50'].IOA
        value = pkt['IOA50'].Value
    else:
        ioa = 0
        value = -1
    if pkt.haslayer('APCI') and pkt['APCI'].Type == 0x00:
        tx = pkt['APCI'].Tx
        rx = pkt['APCI'].Rx
    else:
        tx = 0
        rx = 0
    return {'ioa':ioa,
    'tx':tx,
    'rx':rx,
    'value':value}

def startdt(actcon:bool=False) -> bytes:
    pkt =  APDU()/APCI(ApduLen=4, Type=0x03, UType=0x01 << int(actcon))
    return pkt.build()

def stopdt(actcon:bool=False) -> bytes:
    pkt = APDU()/APCI(ApduLen=4, Type=0x03, UType=0x04 << int(actcon))
    return pkt.build()

def testfr(actcon:bool=False) -> bytes:
    pkt = APDU()/APCI(ApduLen=4, Type=0x03, UType=0x10 << int(actcon))
    return pkt.build()

if __name__ == '__main__':
    print(build_104_asdu_packet(3, 1, 1003, 4, 3, 1, value=67))
    print(build_104_asdu_packet(36, 2, 101, 4, 7, 1, value=54.3))
    print(build_104_asdu_packet(45, 3, 123, 2, 5, 1, SE=1, QU=1, SCS=0))
