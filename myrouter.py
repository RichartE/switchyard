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

        #for intf in net.interfaces():
        #    self.interfaces[intf.name] = intf
        #    for ipa in intf.ipaddrs:
        #        self.arptable[ipa.ip] = intf.ethaddr
        #        self.myips.add(ipa.ip)
        #    self.mymacs.add(intf.ethaddr)
        
        for intf in net.interfaces():
                   print('intf: ' + str(intf))
                   
                   self.interfaces[intf.name] = intf
                   self.mymacs.add(intf.ethaddr)
                   self.arptable[intf.ipaddr] = intf.ethaddr
                   self.myips.add(intf.ipaddr)
                   
                   nexthop = intf.ipaddr
                   prefix = IPv4Address(int(IPv4Address(nexthop)) & int(IPv4Address(intf.netmask)))
                   mask = IPv4Address(intf.netmask)
                   
                   name = intf.name
                   self.forwarding_table.append([str(prefix), str(mask), str(nexthop), str(name)])

        log_debug("My IPs: {}".format(self.myips))

        # *** You will need to add more code to this constructor ***

        # TODO: routing table
        # helpful ref: https://jsommers.github.io/switchyard/_modules/switchyard/lib/testing.html#TestScenario.add_file
        # static_forwarding_table = net._support_files["forwarding_table.txt"].splitlines()
        with open("forwarding_table.txt", 'r') as static_forwarding_table:
            static_entry = static_forwarding_table.readlines()
            for i in static_entry:
                entry = i.split()
                self.forwarding_table.append(entry)
        print('Table:')
        print(self.forwarding_table)

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

    def router_main(self):
        count = 1
        while True:
            try:
                print('helllo')
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)
                print(str(count) + ':')
                count += 1
            except NoPackets:
                log_debug("Timeout waiting for packets")
                continue

            except Shutdown:
                return

            eth = pkt.get_header(Ethernet)

            if eth.ethertype == EtherType.ARP:
                print('yah')
                log_debug("Received ARP packet: {}".format(str(pkt)))
                arp = pkt.get_header(Arp)
                self.arp_responder(dev, eth, arp)

            elif eth.ethertype == EtherType.IP:
                log_debug("Received IP packet: {}".format(str(pkt)))
                print('BYE')
                # TODO: process the IP packet and send out the correct interface
                if pkt[0].dst in self.mymacs:
                    if pkt[1].dst in self.myips:
                        print(pkt)
                        print('one')
                        log_info ("Packet destined to the hub itself.")
                    else:
                        print('two')
                        best_match = -1
                        best_entry = []
                        destaddr = pkt[1].dst
                        # TODO: decrement TTL
                        pkt.get_header(IPv4).ttl -= 1
                        print('t')
                        print('packet: ' + str(pkt))
                        for entry in self.forwarding_table:
                            print()
                            print(entry)
                            print()
                            if entry[2] == str(destaddr):
                                best_match = 100
                                best_entry = entry
                                break
                            print('y')
                            prefixnet = IPv4Network(entry[0]+'/'+entry[1])
                            print('we')
                            matches = destaddr in prefixnet
                            
                            dstt = IPv4Address(str(destaddr))
                            print(str(dstt))
                            prefixx = IPv4Address(entry[0])
                            print(str(prefixx))
                            answ = ((int(prefixx) & int(dstt)) == int(prefixx))
                            print('AHHH:' + str(answ))
                            
                            print('ROUTER: ' + entry[3])
                            print('match: '  +str(matches))
                            print('destination: ' + str(destaddr))
                            print('prefixnet: ' + str(prefixnet))
                            print('prefixlen: ' + str(prefixnet.prefixlen))
            
                            # > 1 matches, the longest prefix match should be used
                            if matches and prefixnet.prefixlen > best_match:
                                best_match = prefixnet.prefixlen
                                best_entry = entry
                        print()
                        print('BEST ENTRY:')
                        print(best_entry)
                        print()
                        print()
                        print('ALL Entries:')
                        for ent in self.forwarding_table:
                            print(ent)
                        print()
                        print()
                        if best_match == -1: # if there is no match, drop packet
                            print('good')
                            log_info ("There is no match in the table.")
                        else: # TODO: correct destination port
                            print('HI')
                            # 1. How are we using the ArpPending object?
                            # TODO: process_arp_pending(), make_arp_request()
                            arp_interface = best_entry[3]
                            next_hop = best_entry[2]
                            print(pkt)
                            packet = (pkt[IPv4] + pkt[ICMP])
                            print('jo')
                            arp_thing = ArpPending(arp_interface, next_hop, packet)
                            print('you shall not pass')
                            self.layer2_forward_list.append(arp_thing)
                            print('three')
                            # arp_stuff = ArpPending(net)
                            # arp_stuff.egress_dev = pkt[0].dst
                            # arp_stuff.nexthop = best_entry[2]
                            # arp_stuff.pkt = pkt
                            # arp_stuff.last_update = time.time()
                            # arp_stuff.attempts = 0
                            #self.layer2_forward_list.append(arp_stuff)

                            # 2. What are we suppsoed to do next?
                            self.process_arp_pending()

                            # arp = pkt.get_header(arp_stuff)
                            # ipv4_h = pkt.get_header(IPv4)
                            # reply_handled = False
                            # if arp:
                            #     srcIP = arp.senderprotoaddr
                            #     destIP = arp.targetprotoaddr
                            #     srcMAC = arp.senderhwaddr
                            #     arp_response = self.make_arp_request(srcMAC, srcIP, destIP)
                            #     self.net.send_packet(best_entry[3],arp_response)

                            # TODO: add to cache (map)
                            self.arptable[pkt.get_header(IPv4)] = pkt[0].dst

                            self.net.send_packet(best_entry[3], pkt)
            else:
                log_warn("Received Non-IP packet that I don't know how to handle: {}".format(str(pkt)))

    def process_arp_pending(self):
        '''
        Once an ArpPending object has been added to the layer 2 forwarding table,
        this method handles the logistics of determining whether an ARP request
        needs to be sent at all, and if so, handles the logistics of sending and
        potentially resending the request.
        '''
        print('go')
        def _ipv4addr(intf):
            v4addrs = [i.ip for i in intf.ipaddrs if i.version == 4]
            return v4addrs[0]

        i = 0
        now = time.time()
        log_info("Processing outstanding packets to be ARPed at {}".format(now))
        newlist = []
        while len(self.layer2_forward_list):
            print('red')
            thisarp = self.layer2_forward_list.pop(0)
            print('THISARP: ' + str(thisarp))
            log_debug("Checking {}".format(str(thisarp)))
            log_debug("Current arp table: {}".format(str(self.arptable)))

            dstmac = None
            # Check: do we already know the MAC address? If so, go ahead and forward
            if thisarp.nexthop in self.arptable:
                dstmac = self.arptable[thisarp.nexthop]
                log_debug("Already have MAC address for {}->{} - don't need to ARP".format(thisarp.nexthop, dstmac))
                # **NOTE: you will need to provide an implementation of layer2_forward
                self.layer2_forward(thisarp.egress_dev, dstmac, thisarp.pkt)
            else:
                # Not in ARP table, so send ARP request if we haven't timed out.
                if thisarp.can_try_again(now):
                    print('warm')
                    
                    arpreq = self.make_arp_request(self.interfaces[thisarp.egress_dev].ethaddr,                                            self.interfaces[thisarp.egress_dev].ipaddr, thisarp.nexthop)
                    
                    print('save me print statements')
                    p = Packet()
                    print('warmer')
                    p += arpreq
                    log_info("ARPing for {} ({})".format(thisarp.nexthop, arpreq))
                    thisarp.add_attempt()
                    print('hot')
                    # **NOTE: you will need to provide an implementation of layer2_forward
                    self.layer2_forward(thisarp.egress_dev, "ff:ff:ff:ff:ff:ff",
                                    p, xtype=EtherType.ARP)
                    newlist.append(thisarp)
                elif thisarp.giveup(now):
                    log_warn("Giving up on ARPing {}".format(str(thisarp.nexthop)))

        self.layer2_forward_list = newlist

    def layer2_forward(self, egress, dstether, a_packet, xtype=EtherType.IP):
        print('vooid')
        eth = Ethernet()
        print('a')
        eth.src = self.interfaces[egress].ethaddr
        eth.dst = EthAddr(dstether)
        print('c')
        eth.ethertype = xtype
        print('b')
        print(type(a_packet))
        print(str(a_packet))
        p = Packet()
        p += eth
        p += a_packet[0]
        print('d')
        print('packet: ' + str(p))
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
