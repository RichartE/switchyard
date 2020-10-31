'''
myrouter.py

Basic IPv4 router template (static routing) in Python, with ARP implemented.

CS 331, Fall 2020
'''

import sys
import os
import time
from collections import namedtuple
from switchyard.lib.userlib import *
from switchyard.lib.address import *

class ArpPending(object):
    '''
    This class handles the mechanics of resending ARP requests, and determining
    when an ARP request should time out.
    '''
    def __init__(self, egress_dev, nexthop, pkt):
        self.egress_dev = egress_dev
        self.nexthop = nexthop
        self.pkt = pkt # packet object with Ethernet header stripped from head
        self.last_update = time.time()
        self.attempts = 0

    def can_try_again(self, timestamp):
        '''
        Returns True if we haven't timed out of ARP request attempts yet,
        and False otherwise.
        '''
        if self.giveup(timestamp):
            return False
        if self.attempts == 0:
            return True
        if (timestamp - self.last_update) >= 1.0:
            return True
        return False

    def add_attempt(self):
        '''
        Accounting method: records the time, and increments the number of attempts,
        each time we re-attempt sending an ARP request.
        '''
        self.last_update = time.time()
        self.attempts += 1

    def giveup(self, timestamp):
        '''
        If we've used up all of our attempts and the timer's expired on the most
        recent attempt, return True. We will send no more ARP requests.
        '''
        return self.attempts == 5 and (timestamp-self.last_update) >= 1.0

    def __str__(self):
        return "Packet to ARP: {} (nexthop: {}, egress: {}, attempts: {} last: {} now: {}".format(str(self.pkt), self.nexthop, self.egress_dev, self.attempts, self.last_update, time.time())

class Router(object):
    '''
    A Router takes in packets and sends them out the correct port.
    '''
    def __init__(self, net):
        self.net = net
        self.arptable = {}
        self.interfaces = {}
        self.mymacs = set()
        self.myips = set()
        self.layer2_forward_list = []
        self.forwarding_table = []
        # Saves the original packet and egress name(router-eth01)
        self.cache ={}
        # Every arp packet is added to the list as well as the ArpPending for the object and egress name(router-eth01)
        self.arpwaitlist = []
        
        for intf in net.interfaces():
                   self.interfaces[intf.name] = intf
                   self.mymacs.add(intf.ethaddr)
                   self.arptable[intf.ipaddr] = intf.ethaddr
                   self.myips.add(intf.ipaddr)
                   
                   # Adds the entries from net.interfaces to the forwarding table
                   nexthop = intf.ipaddr
                   prefix = IPv4Address(int(IPv4Address(nexthop)) & int(IPv4Address(intf.netmask)))
                   mask = IPv4Address(intf.netmask)
                   name = intf.name
                   self.forwarding_table.append([str(prefix), str(mask), str(nexthop), str(name)])

        log_debug("My IPs: {}".format(self.myips))

        # Adds the entries from the file to the forwarding table
        with open("forwarding_table.txt", 'r') as static_forwarding_table:
            static_entry = static_forwarding_table.readlines()
            for i in static_entry:
                entry = i.split()
                self.forwarding_table.append(entry)
       

    def update_arp_table(self, ipaddr, macaddr):
        '''
        Associates the specified IP address with the specified MAC address
        in the ARP table.
        '''
        log_debug("Adding {} -> {} to ARP table".format(ipaddr, macaddr))
        self.arptable[ipaddr] = macaddr

    def arp_responder(self, dev, eth, arp):
        '''
        This is the part of the router that processes ARP requests and determines
        whether to update its ARP table and/or reply to the request
        '''
        # learn what we can from the arriving ARP packet
        if arp.senderprotoaddr != IPv4Address("0.0.0.0") and arp.senderhwaddr != EthAddr("ff:ff:ff:ff:ff:ff"):
            self.update_arp_table(arp.senderprotoaddr, arp.senderhwaddr)

        # if this is a request, reply if the targetprotoaddr is one of our addresses
        if arp.operation == ArpOperation.Request:
            log_debug("ARP request for {}".format(str(arp)))
            if arp.targetprotoaddr in self.myips:
                log_debug("Got ARP for an IP address we know about")
                arpreply = create_ip_arp_reply(self.arptable[arp.targetprotoaddr], eth.src, arp.targetprotoaddr, arp.senderprotoaddr)
                self.update_arp_table(arp.sendpkt.payload.protosrc, pkt.payload.hwsrc)
                self.net.send_packet(dev, arpreply)
        # if this is a reply to a router request construct a packet to send to the destination
        elif arp.targetprotoaddr in self.myips:
            self.arpwaitlist.clear()
            # use the cache to get the proper egress and the original packet
            # the cache key is the router's ethernet address since that is the only constant I could find
            packet, egress = self.cache.pop(arp.targethwaddr, Packet())
            eth = Ethernet()
            eth.src = EthAddr(arp.targethwaddr)
            eth.dst = EthAddr(arp.senderhwaddr)
            eth.ethertype = EtherType.IP
            p = Packet()
            p += eth
            p += packet[IPv4]
            p += packet[ICMP]
            self.net.send_packet(egress, p)

    def router_main(self):
        while True:
            try:
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                #if there is a time out but no ARP pending then simply continue
                if len(self.arpwaitlist) == 0:
                    continue
                log_debug("Timeout waiting for packets")
                now = time.time()
                #check the pending ARP to see if you should resend
                thisarp = self.arpwaitlist[0]
                if self.arpwaitlist[0].can_try_again(now):
                    a = self.arpwaitlist[1]
                    b = self.arpwaitlist[2]
                    self.arpwaitlist[0].add_attempt()
                    self.net.send_packet(a, b)
                # if the router decide to give up on the ARP drop the arp from the list
                elif self.arpwaitlist[0].giveup(now):
                    self.arpwaitlist.clear()
                    log_warn("Giving up on ARPing {}".format(str(thisarp.nexthop)))
                continue

            except Shutdown:
                return
            
            except:
                print("Unexpected error:", sys.exc_info()[0])
                raise
                
            eth = pkt.get_header(Ethernet)

            # if it is an ARP packet go to ARP resonse
            if eth.ethertype == EtherType.ARP:
                log_debug("Received ARP packet: {}".format(str(pkt)))
                arp = pkt.get_header(Arp)
                self.arp_responder(dev, eth, arp)
            
            # if it is an IP packet figure out who it is destined for and attempt to deliver it
            elif eth.ethertype == EtherType.IP:
                log_debug("Received IP packet: {}".format(str(pkt)))
                # Check that the packet is destined for the router's interface
                if pkt[0].dst in self.mymacs:
                    # Check that the packet is not for the router
                    if pkt[1].dst in self.myips:
                        log_info ("Packet destined to the hub itself.")
                    else:
                        # begin matching using forwarding table
                        best_match = -1
                        best_entry = []
                        destaddr = pkt[1].dst
                        # decrement TTL
                        pkt.get_header(IPv4).ttl -= 1
                        # find best match to forward packet
                        for entry in self.forwarding_table:
                            # if the next hop is the destination than the best match is found
                            if entry[2] == str(destaddr):
                                best_match = 100
                                best_entry = entry
                                break
                            prefixnet = IPv4Network(entry[0]+'/'+entry[1])
                            matches = destaddr in prefixnet
                            
                            dstt = IPv4Address(str(destaddr))
                            prefixx = IPv4Address(entry[0])
                            answ = ((int(prefixx) & int(dstt)) == int(prefixx))
            
                            # > 1 matches, the longest prefix match should be used
                            if matches and prefixnet.prefixlen > best_match:
                                best_match = prefixnet.prefixlen
                                best_entry = entry
                                
                        # if there is no match, drop packet
                        if best_match == -1:
                            log_info ("There is no match in the table.")
                        # Create ArpPendingObject with best match
                        else:
                            arp_interface = best_entry[3]
                            next_hop = best_entry[2]
                            packet = (pkt[IPv4] + pkt[ICMP])
                            arp_thing = ArpPending(arp_interface, next_hop, packet)
                            # Add ArpPending to list then process it
                            self.layer2_forward_list.append(arp_thing)
                            self.process_arp_pending()
            else:
                log_warn("Received Non-IP packet that I don't know how to handle: {}".format(str(pkt)))
    def process_arp_pending(self):
        '''
        Once an ArpPending object has been added to the layer 2 forwarding table,
        this method handles the logistics of determining whether an ARP request
        needs to be sent at all, and if so, handles the logistics of sending and
        potentially resending the request.
        '''
        def _ipv4addr(intf):
            v4addrs = [i.ip for i in intf.ipaddrs if i.version == 4]
            return v4addrs[0]

        i = 0
        now = time.time()
        log_info("Processing outstanding packets to be ARPed at {}".format(now))
        newlist = []
        while len(self.layer2_forward_list):
            thisarp = self.layer2_forward_list.pop(0)
            log_debug("Checking {}".format(str(thisarp)))
            log_debug("Current arp table: {}".format(str(self.arptable)))

            dstmac = None
            # Check: do we already know the MAC address of the destination
            if thisarp.pkt[IPv4].dst in self.arptable:
                dstmac = self.arptable[thisarp.pkt[IPv4].dst]
                log_debug("Already have MAC address for {}->{} - don't need to ARP".format(thisarp.nexthop, dstmac))
                # Build and send Packet
                self.layer2_forward(thisarp.egress_dev, dstmac, thisarp.pkt)
            # Not in final destination not in ARP table, so send ARP request if we haven't timed out.
            else:
                #Check if there is already a cache for the interface
                if thisarp.egress_dev not in self.cache:
                    self.cache[self.interfaces[thisarp.egress_dev].ethaddr] = [thisarp.pkt, thisarp.egress_dev]
                # If we haven't yet timed out
                if thisarp.can_try_again(now):
                    # Priority goes to nexthop etheraddress if we don't know it
                    if IPv4Address(str(thisarp.nexthop)) not in self.arptable:
                        arpreq = self.make_arp_request(self.interfaces[thisarp.egress_dev].ethaddr,                                            self.interfaces[thisarp.egress_dev].ipaddr, thisarp.nexthop)
                    # else we want to learn the final destination's etheraddress
                    else:
                        arpreq = self.make_arp_request(self.interfaces[thisarp.egress_dev].ethaddr,                                            self.interfaces[thisarp.egress_dev].ipaddr, thisarp.pkt[IPv4].dst)
                    p = Packet()
                    p += arpreq
                    log_info("ARPing for {} ({})".format(thisarp.nexthop, arpreq))
                    # increment attempt count
                    thisarp.add_attempt()
                    # Clear waitlist and then add current ArpPending to waitlist, my implementation only handles one ARP at a time
                    self.arpwaitlist.clear()
                    self.arpwaitlist.append(thisarp)
                    # Build and send packet
                    self.layer2_forward(thisarp.egress_dev, "ff:ff:ff:ff:ff:ff",
                                    p, xtype=EtherType.ARP)
                # If timed out
                elif thisarp.giveup(now):
                    log_warn("Giving up on ARPing {}".format(str(thisarp.nexthop)))

    def layer2_forward(self, egress, dstether, a_packet, xtype=EtherType.IP):
        '''
        Build a packet that is either IP or ARP then send packet out on egress
        '''
        eth = Ethernet()
        eth.src = self.interfaces[egress].ethaddr
        eth.dst = EthAddr(dstether)
        eth.ethertype = xtype
        p = Packet()
        p += eth
        # IP packet must send differnt headers than the ARP
        if xtype == EtherType.IP:
            p += a_packet[IPv4]
            p += a_packet[ICMP]
        else:
            p += a_packet[0]
            #Arp Packets need to append egress and packet to waitlist so that the packet can be quickly sent when recv_packet times out
            self.arpwaitlist.append(egress)
            self.arpwaitlist.append(p)
        self.net.send_packet(egress, p)
        

    def make_arp_request(self, hwsrc, ipsrc, ipdst):
        arp_req = Arp()
        arp_req.operation = ArpOperation.Request
        arp_req.senderprotoaddr = IPv4Address(ipsrc)
        arp_req.targetprotoaddr = IPv4Address(ipdst)
        arp_req.senderhwaddr = EthAddr(hwsrc)
        arp_req.targethwaddr = EthAddr("ff:ff:ff:ff:ff:ff")
        return arp_req


def main(net):
    '''
    Main entry point for router.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
