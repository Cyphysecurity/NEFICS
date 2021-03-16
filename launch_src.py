#!/usr/bin/env

import sys
import signal
from threading import Thread
from time import sleep
from nefics.rtu import Source, RTU_SOURCE
from nefics.simcomm import SimulationHandler

if __name__ == '__main__':
    if sys.platform[:3] == 'win':
        print('Intended to be executed in a mininet Linux environment.')
        sys.exit()
    srtu = Source(guid=int(sys.argv[1]), type=RTU_SOURCE, voltage=526315.79)
    hrtu = SimulationHandler(srtu)
    def catch_sigterm(s, e):
        global hrtu
        global srtu
        hrtu.terminate = True
        srtu.terminate = True
    signal.signal(signal.SIGINT, catch_sigterm)
    signal.signal(signal.SIGTERM, catch_sigterm)
    mloop = Thread(target=srtu.loop)
    mloop.start()
    hrtu.start()
    print('Source RTU - ID: %d' % srtu.guid)
    while not hrtu.terminate:
        try:
            print('\rVout: {0:5.3f} V'.format(srtu.voltage), end='')
            sleep(1)
        except KeyboardInterrupt:
            hrtu.terminate = True
            srtu.terminate = True
    print('')
    mloop.join()
    hrtu.join()
