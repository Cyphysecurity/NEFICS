#!/usr/bin/env python3

import socket
import errno
from Crypto.Random.random import randint
from threading import Thread
from datetime import datetime
from time import sleep
from binascii import hexlify
from nefics.IEC104.dissector import APDU
from nefics.IEC104.const import *
from nefics.helper104 import *

RTU_TYPES = [           # Supported RTU types
    'SOURCE',
    'TRANSMISSION',
    'LOAD'
]

RTU_SOURCE = 0          # RTU_TYPES index for a "SOURCE" RTU
RTU_TRANSMISSION = 1    # RTU_TYPES index for a "TRANSMISSION" RTU
RTU_LOAD = 2            # RTU_TYPES index for a "LOAD" RTU

RTU_TIMEOUT = 15        # 15-second "T1", as specified in Section 9.6 of 60870-5-104 IEC:2006
SOCK_TIMEOUT = 0.25     # Socket timeout for incoming TCP connections, prevents a blocking listen() in the main thread

RTU_BASE_IOA = 1001     # Arbitrary value indicating the lowest IOA used by the simulation to store measurement values
RTU_BREAKER_BASE = 101  # Arbitrary value indicating the lowest IOA used by the simulation to store breaker status
RTU_NUM_BREAKERS = 3    # Arbitrary value indicating the amount of breakers managed by a Transmission RTU

BREAKERS = dict([(RTU_BREAKER_BASE + i, 2 ** i) for i in range(RTU_NUM_BREAKERS)]) # Breaker status values for a "TRANSMISSION" RTU. The status is handled as a bitfield, one bit per breaker.

IEC104_PORT = 2404      # Standard TCP port used for IEC 60870-5-104
BUFFER_SIZE = 8192      # Receiving buffer size. At most 128 64-byte IOA in a single APDU

class RTU:
    '''
    Base class for all supported RTU types
    
    This class defined the common handling of the different state transitions for the Start/Stop procedure.

    Every sub-class must implement the appropriate measurement and i-frame handling methods.
    '''

    def __init__(self, **kwargs):
        fields = ['guid', 'type']
        if any(k not in kwargs.keys() or not isinstance(kwargs[k], int) for k in fields):
            raise AttributeError()
        self.__guid = kwargs['guid']    # ASDU ID
        self.__type = kwargs['type']    # RTU type
        self.__terminate = False        # Termination flag
        self.__startdt = {}             # State markers for each connection
        self.__tx = 0                   # Transmission counter (0 <= tx <= 65535)
        self.__rx = 0                   # Reception counter (0 <= rx <= 65535)
        self.__confok = False
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        self.__socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.__socket.bind(('0.0.0.0', IEC104_PORT))
        self.__log = open(f'logs/rtu{self.__guid:d}.txt', 'w')
        self.__log.write(f'Instantiated a new {RTU_TYPES[self.__type]:s} RTU.\r\n')

    @property
    def guid(self) -> int:
        return self.__guid
    @guid.setter
    def guid(self, new_guid: int):
        self.__guid = new_guid

    @property
    def rtutype(self) -> int:
        return self.__type
    @rtutype.setter
    def rtutype(self, new_type: int):
        self.__type = new_type

    @property
    def sock(self) -> socket.socket:
        return self.__socket
    @sock.setter
    def sock(self, value: socket.socket):
        self.__socket = value
    
    @property
    def terminate(self) -> bool:
        return self.__terminate
    @terminate.setter
    def terminate(self, value: bool):
        self.__terminate = value

    @property
    def tx(self) -> int:
        return self.__tx
    @tx.setter
    def tx(self, value: int):
        self.__tx = value
    
    @property
    def rx(self) -> int:
        return self.__rx
    @rx.setter
    def rx(self, value: int):
        self.__rx = value
    
    def log(self, msg:str):
        self.__log.write(datetime.now().isoformat() + ' :: ')
        self.__log.write(msg)
        if msg[-2:] != '\r\n':
            self.__log.write('\r\n')
        self.__log.flush()
    
    def __measure(self, wsock:socket.socket, connid:int):
        'Override this method with the appripriate measurement procedure for the specific RTU'
    
    def __handle_iframe(self, wsock:socket.socket, apdu:APDU):
        'Override this method with the appropriate I-frame handling procedure for the specific RTU'
    
    def __subloop(self, wsock: socket.socket):
        'This method handles the state transitions for the Start/Stop procedures'
        connid = randint(0, 65535)
        while connid in self.__startdt.keys():
            connid = randint(0, 65535)
        msr = None
        self.__startdt[connid] = False
        wsock.settimeout(RTU_TIMEOUT)
        self.log(f'Initiating state handler with ID {connid:d}')
        while not self.terminate:
            try:
                data = wsock.recv(BUFFER_SIZE)
                data = APDU(data)
                atype = data['APCI'].Type
                if msr is None: # STOPPED connection as shown in figure 17 from 60870-5-104 IEC:2006
                    if atype in [0x00, 0x01]: # I-frame (0x00) or S-frame (0x01)
                        self.log(f'Received an unexpected frame ({TYPE_APCI[atype]:s}) in "STOPPED connection" state. Terminating thread ...')
                        self.__terminate = True
                    elif atype == 0x03: # U-frame (0x03)
                        ut = data['APCI'].UType
                        if ut == 0x01: # STARTDT act
                            self.log('Received a "STARTDT act" U-frame')
                            data = startdt(True) # STARTDT actcon
                        elif ut == 0x04: # STOPDT act
                            self.log('Received a "STOPDT act" U-frame')
                            data = stopdt(True) # STOPDT actcon
                        else: # TESTFR act
                            self.log('Received a "TESTFR act" U-frame')
                            data = testfr(True) # TESTFR actcon
                        # NOTE: If more than one bit is activated, it will be registered as a 'TESTFR act'
                        wsock.send(data)
                        if ut == 0x01: # Start the connection
                            self._RTU__startdt[connid] = True # Track the state of the current connection
                            msr = Thread(target=self._RTU__measure, kwargs={'wsock': wsock, 'connid': connid})
                            self.log('Start measuring data ...')
                            msr.start() # Start measuring
                else: # STARTED connection as shown in figure 17 from 60870-5-104 IEC:2006
                    if atype == 0x03: # U-frame (0x03)
                        ut = data['APCI'].UType
                        if ut == 0x01: # STARTDT act
                            self.log('Received a "STARTDT act" U-frame')
                            data = startdt(True) # STARTDT actcon
                        elif ut == 0x04: # STOPDT act
                            self.log('Received a "STOPDT act" U-frame')
                            data = stopdt(True) # STOPDT actcon
                            self._RTU__startdt[connid] = False # Change measurement state
                            self.log('Stop measusing data ...')
                            msr.join() # Stop measuring
                            msr = None
                        else: # TESTFR act
                            self.log('Received a "TESTFR act" U-frame')
                            data = testfr(True) # TESTFR actcon
                        wsock.send(data)
                    elif atype == 0x01: # S-frame (0x01)
                        self.log('Received an S-frame')
                        self.__tx = data['APCI'].Rx
                    else: # I-frame (0x00)
                        self.log('Received an I-frame. Initiating handler ...')
                        self.__handle_iframe(wsock, data)
                # NOTE: In this particular simulation, we are not considering the 'Pending UNCONFIRMED STOPPED connection' state, as our responses are faster
            except socket.timeout:
                self.log('ERROR: T1 timeout')
                self.__terminate = True # RTU T1 timeout => terminate connection
            except BrokenPipeError:
                self.log('ERROR: Connection ended unexpectedly')
                self.__terminate = True # Connection ended unexpectedly.
            except socket.error as e:
                if e.errno != errno.ECONNRESET:
                    self.log(f'ERROR: Unknown socket error: {e.errno:d}')
                    raise # Other unknown error
                self.__terminate = True
            except IndexError:
                self.log('ERROR: Index error')
        if msr is not None: # The connection was still measuring
            self.__startdt[connid] = False # Change measurement state
            msr.join() # Stop measuring
            msr = None
            self.__startdt.pop(connid) # Remove the connection tracking
        wsock.close()

    def loop(self):
        'This method handles the raw TCP listening socket, accepting new incoming connections.'
        self.log(f'Listening for incoming connections ...')
        self.sock.settimeout(SOCK_TIMEOUT)
        self.sock.listen()
        threads = []
        while not self.terminate:
            try:
                wsock, addr = self.sock.accept() # Accept a new connection
                self.log(f'Incoming connection from {str(addr):s}')
                if not self.__confok or len(threads) == 0:
                    wsock.settimeout(SOCK_TIMEOUT)
                    self.log(f'Creating state transition handler for {str(addr):s}')
                    t = Thread(target=self.__subloop, kwargs={'wsock': wsock}) # Create a state transition handler
                    threads.append(t) # Keep track of all the incoming connections
                    t.start() # Start the state transition handler for this new connection
                else:
                    self.log(f'Connection from {str(addr):s} rejected. only one connection allowed.')
                    wsock.close()
            except socket.timeout:
                pass
        for t in threads:
            t.join()
        self.sock.close()
        self.__log.close()
    
    def __str__(self):
        return 'RTU\r\n------------------\r\nID: {0:11d}\r\nType: {1:12s}'.format(self.__guid, RTU_TYPES[self.__type])
    
    def __repr__(self):
        return 'RTU({0:d}, {1:d})'.format(self.__guid, self.__type)

class Source(RTU):

    def __init__(self, **kwargs):
        super(Source, self).__init__(**kwargs)
        if 'voltage' not in kwargs.keys() or not isinstance(kwargs['voltage'], float):
            raise AttributeError()
        self.__voltage = kwargs['voltage']
        self.__confok = False

    @property
    def voltage(self) -> float:
        return self.__voltage
    @voltage.setter
    def voltage(self, value: float):
        self.__voltage = value
    
    def __str__(self):
        return 'Source RTU\r\n----------------\r\nID: {0:11d}\r\nVout: {1:6.2f}'.format(self.guid, self.__voltage)
    
    def __repr__(self):
        return 'Source RTU ({0:d}, {1:.2f})'.format(self.guid, self.__voltage)

    def _RTU__measure(self, connid: int, wsock: socket.socket):
        self.log(f'Measurement thread started')
        while self._RTU__startdt[connid]:
            if all(x is not None for x in [self.tx, self.rx]):
                # ASDU Type 36: M_ME_TF_1
                data = build_104_asdu_packet(36, self.guid, RTU_BASE_IOA, self.tx, self.rx, 3, value=self.__voltage)
                self.log(f'Sending measured data: {repr(APDU(data))}')
                self.tx += 1
                if self.tx == 65536:
                    self.tx = 0
                try:
                    wsock.send(data)
                except BrokenPipeError:
                    break
                except socket.error as e:
                    if e.errno != errno.ECONNRESET:
                        raise
                    break
            sleep(1)
    
    def _RTU__handle_iframe(self, wsock, apdu):
        data = apdu
        self.rx += 1
        self.tx = apdu['APCI'].Rx
        data['APCI'].Tx = self.tx
        self.tx += 1
        data['APCI'].Rx = self.rx
        data['ASDU'].CauseTx = 45       # Cause of transmission: Unknown cause of transmission. A source RTU should not receive any commands.
        wsock.send(data)
    
    def loop(self):
        super().loop()

class Transmission(RTU):

    def __init__(self, **kwargs):
        super(Transmission, self).__init__(**kwargs)
        if any(k not in kwargs.keys() for k in ['state', 'loads', 'left', 'right', 'confok']):
            raise AttributeError()
        if any(not isinstance(kwargs[k], int) for k in ['state', 'left', 'right']) or not isinstance(kwargs['loads'], list):
            raise AttributeError()
        if any(not isinstance(k, float) for k in kwargs['loads']):
            raise AttributeError()
        if not isinstance(kwargs['confok'], bool):
            raise AttributeError()
        self.__state = kwargs['state']
        self.__loads = kwargs['loads']
        self.__left = kwargs['left']
        self.__right = kwargs['right']
        self.__confok = kwargs['confok']
        self.__load = None
        self.__vin = None
        self.__vout = None
        self.__amp = None
        self.__rload = None
        self.__wait_exec = None

    @property
    def state(self) -> float:
        return self.__state
    @state.setter
    def state(self, value: float):
        self.__state = value

    @property
    def left(self) -> float:
        return self.__left
    @left.setter
    def left(self, value: float):
        self.__left = value

    @property
    def right(self) -> float:
        return self.__right
    @right.setter
    def right(self, value: float):
        self.__right = value

    @property
    def load(self) -> float:
        return self.__load
    @load.setter
    def load(self, value: float):
        self.__load = value

    @property
    def vin(self) -> float:
        return self.__vin
    @vin.setter
    def vin(self, value: float):
        self.__vin = value

    @property
    def vout(self) -> float:
        return self.__vout
    @vout.setter
    def vout(self, value: float):
        self.__vout = value
    
    @property
    def rload(self) -> float:
        return self.__rload
    @rload.setter
    def rload(self, value: float):
        self.__rload = value
    
    @property
    def amp(self) -> float:
        return self.__amp
    @amp.setter
    def amp(self, value: float):
        self.__amp = value

    def calculate_load(self):
        self.__load = None
        if self.__state == 0:
            self.__load = float('inf')
            return
        for i in range(len(self.__loads)): # Iterate over the breakers
            if (self.__state & (2 ** i)) == 0: # If the current breaker is 'OFF' => Corresponding load is connected
                if self.__loads[i] == 0:    # Load == 0 => Failure (not yet implemented)
                    self.__load = 0
                    return
                self.__load = self.__loads[i] if self.__load is None else (self.__load * self.__loads[i]) / (self.__load + self.__loads[i])

    def __increment_counters(self, rx:int=None, tx:int=None):
        '''
        Increment the internal RX and TX counters.

        The parameters rx end tx refer to the Rx and Tx in the APCI layer of the received packet, if any.
        '''
        self.tx = rx if rx is not None else self.tx + 1
        self.rx = tx if tx is not None else self.rx + 1
        if self.tx >= 65536:
            self.tx = 0
        if self.rx >= 65536:
            self.rx = 0

    def _RTU__handle_iframe(self, wsock, apdu):
        try:
            self.log(f'Handling {repr(apdu)} ...')
            asdu = apdu['ASDU']
            if asdu.TypeId == 45: # C_SC_NA_1 defined in section 7.3.2.1 of 60870-5-101 IEC:2003
                self.log(f'Identified an type 45 ASDU (C_SC_NA_1) SELECT={asdu["IOA45"].SCO.SE} CTX={asdu.CauseTx}.')
                self.__increment_counters(apdu['APCI'].Rx + 1, apdu['APCI'].Tx + 1)
                if self.__wait_exec is None and asdu['IOA45'].SCO.SE == 1 and asdu.CauseTx == 6: # SCO: Select; Cause of transmission: Activation
                    self.log(f'Received a new C_SC_NA_1 (ASDU type 45) SELECT - Activation. Checking IOA ID ...')
                    if asdu['IOA45'].IOA in BREAKERS.keys():
                        self.log(f'Received an appropriate new C_SC_NA_1 (ASDU type 45) SELECT - Activation')
                        self.__wait_exec = asdu['IOA45'].IOA
                        data = build_104_asdu_packet(45, self.guid, asdu['IOA45'].IOA, self.tx, self.rx, 7, SE=asdu['IOA45'].SCO.SE, QU=asdu['IOA45'].SCO.QU, SCS=asdu['IOA45'].SCO.SCS) # SCO: Select; Cause of transmission: Activation Confirmation
                    else:
                        self.log(f'''WARNING: Received a new C_SC_NA_1 (ASDU type 45) SELECT - Activation with an unknown IOA: {asdu['IOA45'].IOA}''')
                        data = build_104_asdu_packet(45, self.guid, asdu['IOA45'].IOA, self.tx, self.rx, 47, SE=asdu['IOA45'].SCO.SE, QU=asdu['IOA45'].SCO.QU, SCS=asdu['IOA45'].SCO.SCS) # SCO: Select; Cause of transmission: Unknown information object address
                elif self.__wait_exec is not None and asdu['IOA45'].SCO.SE == 0x00 and asdu.CauseTx == 6: # SCO: Execute; Cause of transmission: Activation
                    if self.__wait_exec == asdu['IOA45'].IOA:
                        self.log(f'''Received a new C_SC_NA_1 (ASDU type 45) EXECUTE - Activation''')
                        data = build_104_asdu_packet(45, self.guid, asdu['IOA45'].IOA, self.tx, self.rx, 7, SE=asdu['IOA45'].SCO.SE, QU=asdu['IOA45'].SCO.QU, SCS=asdu['IOA45'].SCO.SCS) # SCO: Execute; Cause of transmission: Activation Confirmation
                        if bool(asdu['IOA45'].SCO.SCS):
                            self.__state = self.__state | BREAKERS[self.__wait_exec] # STATE OR IOA
                        else: 
                            self.__state = self.__state & (BREAKERS[self.__wait_exec] ^ ((2 ** RTU_NUM_BREAKERS) - 1)) # STATE AND (IOA XOR 1...11)
                    else:
                        self.log(f'''WARNING: Received a new C_SC_NA_1 (ASDU type 45) EXECUTE - Activation for an unexpected IOA: {asdu['IOA45'].IOA}''')
                        data = build_104_asdu_packet(45, self.guid, asdu['IOA45'].IOA, self.tx, self.rx, 47, SE=asdu['IOA45'].SCO.SE, QU=asdu['IOA45'].SCO.QU, SCS=asdu['IOA45'].SCO.SCS) # SCO: Execute; Cause of transmission: Unknown information object address
                elif self.__wait_exec is not None and asdu['IOA45'].SCO.SE == 1 and asdu.CauseTx == 8: # SCO: Select; Cause of transmission: Deactivation
                    self.log(f'''Received a new C_SC_NA_1 (ASDU type 45) SELECT - Deactivation''')
                    data = build_104_asdu_packet(45, self.guid, asdu['IOA45'].IOA, self.tx, self.rx, 9, SE=asdu['IOA45'].SCO.SE, QU=asdu['IOA45'].SCO.QU, SCS=asdu['IOA45'].SCO.SCS) # SCO: Select; Cause of transmission: Deactivation Confirmation
                    self.__wait_exec = None
                else:
                    self.log(f'''WARNING: Received an unexpected C_SC_NA_1 (ASDU type 45) EXECUTE''')
                    data = apdu
                    data['APCI'].Rx = self.rx
                    data['APCI'].Tx = self.tx
                    data['ASDU'].CauseTx = 45 # Cause of transmission: Unknown cause of transmission
                    data = data.build()
            else:
                self.log(f'''WARNING: Received an unexpected ASDU (type {asdu.TypeId}''')
                data = apdu
                data['APCI'].Rx = self.rx
                data['APCI'].Tx = self.tx
                data['ASDU'].CauseTx = 45 # Cause of transmission: Unknown cause of transmission
                data = data.build()
            self.log(f'Sending I-frame response: {repr(APDU(data))}')
            wsock.send(data)
        except socket.timeout:
            self.log('T1 timeout')
            self.terminate =  True
        except BrokenPipeError:
            pass
        except socket.error as e:
            if e.errno != errno.ECONNRESET:
                raise
        except IndexError as e:
            self.log(f'IndexError: {str(e)}')
    
    def _RTU__measure(self, wsock: socket.socket, connid:int):
        while self._RTU__startdt[connid]:
            if all(x is not None for x in [self.tx, self.rx]):
                try:
                    self.log(f'Sending measured input voltage ...')
                    data = build_104_asdu_packet(36, self.guid, RTU_BASE_IOA, self.tx, self.rx, 3, value=self.__vin)
                    self.tx += 1
                    if self.tx == 65536:
                        self.tx = 0
                    wsock.send(data)
                    self.log(f'Sending measured current ...')
                    data = build_104_asdu_packet(36, self.guid, RTU_BASE_IOA + 1, self.tx, self.rx, 3, value=self.__amp)
                    self.tx += 1
                    if self.tx == 65536:
                        self.tx = 0
                    wsock.send(data)
                    self.log(f'Sending breaker states ... ')
                    for i in range(len(self.__loads)):
                        data = build_104_asdu_packet(3, self.guid, RTU_BREAKER_BASE + i, self.tx, self.rx, 3, value=int(0x01 if ((self.__state & BREAKERS[RTU_BREAKER_BASE + i]) > 0) else 0x02))
                        self.log(f'Sending breaker {RTU_BREAKER_BASE + i}: {repr(APDU(data))}')
                        self.tx += 1
                        if self.tx == 65536:
                            self.tx = 0
                        wsock.send(data)
                except BrokenPipeError:
                    break
                except socket.error as e:
                    if e.errno != errno.ECONNRESET:
                        raise
                    break
                except Exception as e:
                    self.log(str(e))
            sleep(1)
    
class Load(RTU):

    def __init__(self, **kwargs):
        super(Load, self).__init__(**kwargs)
        if any(k not in kwargs.keys() for k in ['load', 'left']):
            raise AttributeError()
        if not isinstance(kwargs['load'], float) or not isinstance(kwargs['left'], int):
            raise AttributeError()
        self.__load = kwargs['load']
        self.__left = kwargs['left']
        self.__confok = False
        self.__vin = None
        self.__amp = None

    @property
    def load(self) -> float:
        return self.__load
    @load.setter
    def load(self, new_load: float):
        self.__load = new_load
    
    @property
    def left(self) -> int:
        return self.__left
    @left.setter
    def left(self, value: int):
        self.__left = value

    @property
    def vin(self) -> float:
        return self.__vin
    @vin.setter
    def vin(self, value: float):
        self.__vin = value

    def __str__(self):
        return 'Load RTU\r\n-------------------\r\nID: {0:14d}\r\nLoad: {1:9.2f}'.format(self.guid, self.__load)
    
    def __repr__(self):
        return 'Load RTU ({0:d}, {1:.2f})'.format(self.guid, self.__load)

    def _RTU__measure(self, wsock: socket.socket, connid:int):
        while self._RTU__startdt[connid]:
            if all(x is not None for x in [self.tx, self.rx]):
                try:
                    data = build_104_asdu_packet(36, self.guid, RTU_BASE_IOA, self.tx, self.rx, 3, value=self.__vin)
                    self.log(f'Sending measured voltage ... {repr(APDU(data))}')
                    self.tx += 1
                    if self.tx == 65536:
                        self.tx = 0
                    wsock.send(data)
                    data = build_104_asdu_packet(36, self.guid, RTU_BASE_IOA + 1, self.tx, self.rx, 3, value=self.__amp)
                    self.log(f'Sending measured current ... {repr(APDU(data))}')
                    self.tx += 1
                    if self.tx == 65536:
                        self.tx = 0
                    wsock.send(data)
                except BrokenPipeError:
                    break
                except socket.error as e:
                    if e.errno != errno.ECONNRESET:
                        raise
                    break
            sleep(1)
    
    def _RTU__handle_iframe(self, wsock, apdu):
        self.rx += 1
        self.tx = apdu['APCI'].Rx
        data = apdu
        data['APCI'].Tx = self.tx
        self.tx += 1
        data['APCI'].Rx = self.rx
        data['ASDU'].CauseTx = 45
        wsock.send(data)
