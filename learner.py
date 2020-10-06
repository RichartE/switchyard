
'''learner.py
TEAM E: Aishee Mukherji, Eric Odoom, Etienne Richart
'''
from switchyard.lib.userlib import *
import datetime

class Address():
    def __init__(self, addr, port, timestamp):
        self.addr = addr
        self.port = port
        self.timestamp = timestamp

    def __str__(self):
        return "{} on port {}. Traffic: {}".format(self.addr, self.port, self.timestamp)

addrs = []

def learnAddress(src, input_port):
    global addrs
    removeStale()
    nextAddress = next((a for a in addrs if a.addr == src), None)
    if nextAddress:
        nextAddress.port = input_port
        nextAddress.timestamp = datetime.datetime.now()
    else:
        addrs.sort(key=lambda x: x.timestamp, reverse = True)
        addrs = addrs[:10]
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
    for x in range(len(addrs)):
        if (datetime.datetime.now() - addrs[x].timestamp).seconds > 30:
            addrs.pop(x)
            
