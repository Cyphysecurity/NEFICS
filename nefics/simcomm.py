#!/usr/bin/env python3

import sys
import socket
import random
from time import sleep
from struct import pack, unpack
from threading import Thread
from nefics.rtu import RTU, RTU_SOURCE, RTU_TRANSMISSION, RTU_LOAD, RTU_TYPES

if sys.platform[:3] == 'win':
    print('Intended to be executed in a mininet Linux environment.')
    raise RuntimeError()

try:
    from pyroute2 import IPDB
except ImportError:
    print('Dependency missing: pip install pyroute2')
    sys.exit(1)
ip = IPDB()
SIM_BCAST = ip.interfaces[[x for x in ip.interfaces if ip.interfaces[x]['state'] == 'up' and isinstance(x, str) and str(x) != 'lo'][0]].ipaddr[0]['broadcast']
ip.release()
del ip

SIM_PORT = 20202        # UDP port used for the simulation information exchange between the different RTUs
BUFFER_SIZE = 512
DATA_FMT = '<IIIIIff'   # Sender-ID Receiver-ID Message-ID IARG-0 IARG-1 FARG-0 FARG-1

# Message ID
MSG_WERE = 0
MSG_ISAT = 1
MSG_GETV = 2
MSG_VOLT = 3
MSG_GREQ = 4
MSG_TREQ = 5
MSG_UKWN = 99

class ClassTypeMismatch(Exception):
    pass

class SimulationHandler(Thread):

    def __init__(self, rtu):
        super(SimulationHandler, self).__init__()
        if rtu is None or rtu.__class__.__name__ not in ['Load', 'Transmission', 'Source'] or not isinstance(rtu, RTU):
            raise AttributeError()
        self.__rtu = rtu
        self.__terminate = False
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)      # Use UDP
        if sys.platform not in ['win32']:
            self.__sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)                   # Enable port reusage pylint: disable=no-member
        self.__sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)                       # Enable address reuse
        self.__sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)                       # Enable broadcast
        self.__sock.bind(('', SIM_PORT))
        self.__sock.settimeout(0.333)
        self.__laddr = None
        self.__raddr = None
    
    @property
    def terminate(self) -> bool:
        return self.__terminate
    @terminate.setter
    def terminate(self, value: bool):
        self.__terminate = value
    
    def who_has_left(self):
        count = 0
        while not self.__terminate and self.__laddr is None:
            try:
                # if (count % 10) == 0:
                data = pack(DATA_FMT, self.__rtu.guid, self.__rtu.left, MSG_WERE, 0, 0, 0.0, 0.0)
                self.__sock.sendto(data, (SIM_BCAST, SIM_PORT))
                sleep(round(random.random(), 2))
                data, addr = self.__sock.recvfrom(BUFFER_SIZE)
                data = unpack(DATA_FMT, data)
                if data[0] == self.__rtu.left:
                    self.__laddr = addr
                elif data[2] == MSG_WERE and data[1] == self.__rtu.guid:
                    data = pack(DATA_FMT, self.__rtu.guid, data[0], MSG_ISAT, 0, 0, 0.0, 0.0)
                    self.__sock.sendto(data, addr)
            except socket.timeout:
                pass
            count +=1
    
    def who_has_right(self):
        count = 0
        while not self.__terminate and self.__raddr is None:
            try:
                # if (count % 10) == 0:
                data = pack(DATA_FMT, self.__rtu.guid, self.__rtu.right, MSG_WERE, 0, 0, 0.0, 0.0)
                self.__sock.sendto(data, (SIM_BCAST, SIM_PORT))
                sleep(round(random.random(), 2))
                data, addr = self.__sock.recvfrom(BUFFER_SIZE)
                data = unpack(DATA_FMT, data)
                if data[0] == self.__rtu.right:
                    self.__raddr = addr
                elif data[2] == MSG_WERE and data[1] == self.__rtu.guid:
                    data = pack(DATA_FMT, self.__rtu.guid, data[0], MSG_ISAT, 0, 0, 0.0, 0.0)
                    self.__sock.sendto(data, addr)
            except socket.timeout:
                pass
            count +=1
    
    def vin_polling(self):
        while not self.__terminate:
            data = pack(DATA_FMT, self.__rtu.guid, self.__rtu.left, MSG_GETV, 0, 0, 0.0, 0.0)
            self.__sock.sendto(data, self.__laddr)
            sleep(0.5)
    
    def rload_polling(self):
        while not self.__terminate:
            data = pack(DATA_FMT, self.__rtu.guid, self.__rtu.right, MSG_GREQ, 0, 0, 0.0, 0.0)
            self.__sock.sendto(data, self.__raddr)
            sleep(0.5)

    def measurements(self):
        last_state = None
        while not self.__terminate:
            if self.__rtu.state != last_state:
                self.__rtu.calculate_load()
                last_state = self.__rtu.state
            if self.__rtu.load == float('inf'):
                self.__rtu.vout = 0
                self.__rtu.amp = 0
            elif all(x is not None for x in [self.__rtu.vin, self.__rtu.load, self.__rtu.rload]):
                load = self.__rtu.load
                vin = self.__rtu.vin
                rload = self.__rtu.rload
                if rload == float('inf'):
                    self.__rtu.vout = vin
                else:
                    self.__rtu.vout = vin  * rload / (rload + load)
                try:
                    self.__rtu.amp = vin / rload
                except ZeroDivisionError:
                    self.__rtu.amp = float('inf')
            sleep(0.333)
    
    def run_source(self):
        while not self.__terminate:
            try:
                data, addr = self.__sock.recvfrom(BUFFER_SIZE)
                data = unpack(DATA_FMT, data) 
                if data[1] == self.__rtu.guid:
                    if data[2] == MSG_WERE:
                        data = pack(DATA_FMT, self.__rtu.guid, data[0], MSG_ISAT, 0, 0, 0.0, 0.0)
                    elif data[2] == MSG_GETV:
                        data = pack(DATA_FMT, self.__rtu.guid, data[0], MSG_VOLT, 0, 0, self.__rtu.voltage, 0.0)
                    elif data[2] == MSG_UKWN:
                        data = None
                        # sys.stderr.write('Received MSG_UKWN from {:s}\r\n'.format(addr[0]))
                        sys.stderr.flush()
                    else:
                        data = pack(DATA_FMT, self.__rtu.guid, data[0], MSG_UKWN, 0, 0, 0.0, 0.0)
                    if data is not None:
                        self.__sock.sendto(data, addr)
            except socket.timeout:
                pass

    def run_transmission(self):
        vpoller = Thread(target=self.vin_polling)
        rpoller = Thread(target=self.rload_polling)
        measure = Thread(target=self.measurements)
        vpoller.start()
        rpoller.start()
        measure.start()
        while not self.__terminate:
            try:
                data, addr = self.__sock.recvfrom(BUFFER_SIZE)
                data = unpack(DATA_FMT, data)
                if data[1] == self.__rtu.guid:
                    if data[2] == MSG_WERE:
                        data = pack(DATA_FMT, self.__rtu.guid, data[0], MSG_ISAT, 0, 0, 0.0, 0.0)
                    elif data[2] == MSG_GETV:
                        data = pack(DATA_FMT, self.__rtu.guid, data[0], MSG_VOLT, 0, 0, self.__rtu.vout, 0.0) if self.__rtu.vout is not None else None
                    elif data[2] == MSG_VOLT:
                        self.__rtu.vin = data[5]
                        data = None
                    elif data[2] == MSG_GREQ:
                        data = pack(DATA_FMT, self.__rtu.guid, data[0], MSG_TREQ, 0, 0, self.__rtu.load + self.__rtu.rload, 0.0) if all(x is not None for x in [self.__rtu.rload, self.__rtu.load]) else None
                    elif data[2] == MSG_TREQ:
                        self.__rtu.rload = data[5]
                        data = None
                    elif data[2] == MSG_UKWN:
                        data = None
                        # sys.stderr.write('Received MSG_UKWN from {:s}\r\n'.format(addr[0]))
                        sys.stderr.flush()
                    else:
                        data = pack(DATA_FMT, self.__rtu.guid, data[0], MSG_UKWN, 0, 0, 0.0, 0.0)
                    if data is not None:
                        self.__sock.sendto(data, addr)
            except socket.timeout:
                pass
        vpoller.join()
        rpoller.join()
        measure.join()

    def run_load(self):
        vpoller = Thread(target=self.vin_polling)
        vpoller.start()
        while not self.__terminate:
            try:
                data, addr = self.__sock.recvfrom(BUFFER_SIZE)
                data = unpack(DATA_FMT, data)
                if data[1] == self.__rtu.guid:
                    if data[2] == MSG_WERE:
                        data = pack(DATA_FMT, self.__rtu.guid, data[0], MSG_ISAT, 0, 0, 0.0, 0.0)
                    elif data[2] == MSG_GREQ:
                        data = pack(DATA_FMT, self.__rtu.guid, data[0], MSG_TREQ, 0, 0, self.__rtu.load, 0.0)
                    elif data[2] == MSG_VOLT:
                        self.__rtu.vin = data[5]
                        data = None
                    elif data[2] == MSG_UKWN:
                        data = None
                        # sys.stderr.write('Received MSG_UKWN from {:s}\r\n'.format(addr[0]))
                        sys.stderr.flush()
                    else:
                        data = pack(DATA_FMT, self.__rtu.guid, data[0], MSG_UKWN, 0, 0, 0.0, 0.0)
                    if data is not None:
                        self.__sock.sendto(data, addr)
            except socket.timeout:
                pass
        vpoller.join()   

    def run(self):
        if self.__rtu.rtutype == RTU_SOURCE and self.__rtu.__class__.__name__ == 'Source':
            self.run_source()
        elif self.__rtu.rtutype == RTU_LOAD and self.__rtu.__class__.__name__ == 'Load':
            self.who_has_left()
            self.run_load()
        elif self.__rtu.rtutype == RTU_TRANSMISSION and self.__rtu.__class__.__name__ == 'Transmission':
            self.who_has_left()
            self.who_has_right()
            self.run_transmission()
        else:
            raise ClassTypeMismatch()
        self.__sock.close()
