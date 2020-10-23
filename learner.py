
'''learner.py
TEAM E: Aishee Mukherji, Eric Odoom, Etienne Richart
'''
from switchyard.lib.userlib import *
import datetime
import time

class Address():
    def __init__(self, addr, port, timestamp):
        self.addr = addr
        self.port = port
        self.timestamp = timestamp

    def __str__(self):
        return "{} on port {}. Traffic: {}. Microsecond {}".format(self.addr, self.port, self.timestamp, (datetime.datetime.now() - self.timestamp).microseconds)

addrs = []
tableSize = 10
#timeout in microseconds
staleTime = 1000


def learnAddress(src, input_port):
    global addrs
    removeStale()
    nextAddress = next((a for a in addrs if a.addr == src), None)
    if nextAddress:
        nextAddress.port = input_port
        nextAddress.timestamp = datetime.datetime.now()
    else:
        addrs.sort(key=lambda x: x.timestamp, reverse = True)
        addrs = addrs[:tableSize - 1]
        addrs.append(Address(src, input_port, datetime.datetime.now()))
    log_debug("Learn: {}".format(addrs))

def getAddress(dest):
    global addrs
    removeStale()
    nextAddress = next((a for a in addrs if a.addr == dest), None)
    if nextAddress:
        addrs.pop(addrs.index(nextAddress))
        nextAddress.timestamp = datetime.datetime.now()
        addrs.append(nextAddress)
        return nextAddress.port
    return None
    
def removeStale():
    global addrs
    def filt(timedelta):
        if (datetime.datetime.now() - timedelta.timestamp).microseconds > staleTime:
            return False
        else:
            return True
    addrs = list(filter(filt, addrs))
    
def debug(count):
    global addrs
    print('Debug '+ str(count) + ': ' + str(datetime.datetime.now()) + ': ')
    [print(i) for i in addrs]
    print()
