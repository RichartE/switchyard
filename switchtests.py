#!/usr/bin/env python3

from switchyard.lib.userlib import *
import time


def mk_pkt(hwsrc, hwdst, ipsrc, ipdst, reply=False):
    ether = Ethernet(src=hwsrc,dst=hwdst,ethertype=EtherType.IPv4)
    ippkt = IPv4(src=ipsrc,dst=ipdst,protocol=IPProtocol.ICMP,ttl=32)
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    icmppkt.icmpcode = 0
    icmppkt.icmpdata.sequence = 42
    return ether + ippkt + icmppkt

def learning_switch_tests():
    s = TestScenario("learning switch tests")
    s.add_interface('eth0', '10:00:00:00:00:01', '192.168.1.1', '255.255.255.0')
    s.add_interface('eth1', '10:00:00:00:00:02', '10.10.0.1', '255.255.0.0')
    s.add_interface('eth2', '10:00:00:00:00:03', '172.16.42.1', '255.255.255.252')

    reqpkt = mk_pkt("20:00:00:00:00:01", "30:00:00:00:00:02", '192.168.1.100','172.16.42.2')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), 
        "Ethernet frame from 20:00:00:00:00:01 to 30:00:00:00:00:02 with unknown destination port should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt, "eth2", reqpkt, display=Ethernet),
        "Ethernet frame destined for 30:00:00:00:00:02 should be flooded out eth1 and eth2")

    resppkt = mk_pkt("30:00:00:00:00:02", "20:00:00:00:00:01", '172.16.42.2', '192.168.1.100', reply=True)
    s.expect(PacketInputEvent("eth1", resppkt, display=Ethernet), 
        "Ethernet frame from 30:00:00:00:00:02 to 20:00:00:00:00:01 should arrive on eth1")
    s.expect(PacketOutputEvent("eth0", resppkt, display=Ethernet), 
        "Ethernet frame destined to 20:00:00:00:00:01 should be forwarded directly to eth0 since that MAC address should have been learned.")

    testpkt = mk_pkt("30:00:00:00:00:02", "ff:ff:ff:ff:ff:ff", "172.16.42.2", "255.255.255.255")
    s.expect(PacketInputEvent("eth1", testpkt, display=Ethernet), 
        "An Ethernet frame with a broadcast destination address should arrive on eth1")
    s.expect(PacketOutputEvent("eth0", testpkt, "eth2", testpkt, display=Ethernet),
        "The Ethernet frame with a broadcast destination address should be forwarded out ports eth0 and eth2")
        
    reqpkt = mk_pkt("40:00:00:00:00:01", "30:00:00:00:00:03", '192.168.1.103','172.16.42.3')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet),
        "Ethernet frame from 20:00:00:00:00:01 to 30:00:00:00:00:02 with unknown destination port should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt, "eth2", reqpkt, display=Ethernet),
        "Ethernet frame destined for 30:00:00:00:00:02 should be flooded out eth1 and eth2")
        
    reqpkt = mk_pkt("40:00:00:00:00:02", "30:00:00:00:00:03", '192.168.1.103','172.16.42.3')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet),
        "Ethernet frame from 20:00:00:00:00:01 to 30:00:00:00:00:02 with unknown destination port should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt, "eth2", reqpkt, display=Ethernet),
        "Ethernet frame destined for 30:00:00:00:00:02 should be flooded out eth1 and eth2")
        
    reqpkt = mk_pkt("40:00:00:00:00:03", "30:00:00:00:00:03", '192.168.1.103','172.16.42.3')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet),
        "Ethernet frame from 20:00:00:00:00:01 to 30:00:00:00:00:02 with unknown destination port should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt, "eth2", reqpkt, display=Ethernet),
        "Ethernet frame destined for 30:00:00:00:00:02 should be flooded out eth1 and eth2")
        
    reqpkt = mk_pkt("40:00:00:00:00:03", "30:00:00:00:00:03", '192.168.1.103','172.16.42.3')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet),
        "Ethernet frame from 20:00:00:00:00:01 to 30:00:00:00:00:02 with unknown destination port should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt, "eth2", reqpkt, display=Ethernet),
        "Ethernet frame destined for 30:00:00:00:00:02 should be flooded out eth1 and eth2")
        
    reqpkt = mk_pkt("20:00:00:00:00:05", "30:00:00:00:00:03", '192.168.1.103','172.16.42.3')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet),
        "Ethernet frame from 20:00:00:00:00:01 to 30:00:00:00:00:02 with unknown destination port should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt, "eth2", reqpkt, display=Ethernet),
        "Ethernet frame destined for 30:00:00:00:00:02 should be flooded out eth1 and eth2")
        
    reqpkt = mk_pkt("20:00:00:00:00:06", "30:00:00:00:00:03", '192.168.1.103','172.16.42.3')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet),
        "Ethernet frame from 20:00:00:00:00:01 to 30:00:00:00:00:02 with unknown destination port should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt, "eth2", reqpkt, display=Ethernet),
        "Ethernet frame destined for 30:00:00:00:00:02 should be flooded out eth1 and eth2")
    
    reqpkt = mk_pkt("20:00:00:00:00:07", "30:00:00:00:00:03", '192.168.1.103','172.16.42.3')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet),
        "Ethernet frame from 20:00:00:00:00:01 to 30:00:00:00:00:02 with unknown destination port should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt, "eth2", reqpkt, display=Ethernet),
        "Ethernet frame destined for 30:00:00:00:00:02 should be flooded out eth1 and eth2")
        
    reqpkt = mk_pkt("20:00:00:00:00:08", "30:00:00:00:00:03", '192.168.1.103','172.16.42.3')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet),
        "Ethernet frame from 20:00:00:00:00:01 to 30:00:00:00:00:02 with unknown destination port should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt, "eth2", reqpkt, display=Ethernet),
        "Ethernet frame destined for 30:00:00:00:00:02 should be flooded out eth1 and eth2")
    
    reqpkt = mk_pkt("20:00:00:00:00:09", "30:00:00:00:00:03", '192.168.1.103','172.16.42.3')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet),
        "Ethernet frame from 20:00:00:00:00:01 to 30:00:00:00:00:02 with unknown destination port should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt, "eth2", reqpkt, display=Ethernet),
        "Ethernet frame destined for 30:00:00:00:00:02 should be flooded out eth1 and eth2")
        
    reqpkt = mk_pkt("20:00:00:00:00:10", "30:00:00:00:00:03", '192.168.1.103','172.16.42.3')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet),
        "Ethernet frame from 20:00:00:00:00:01 to 30:00:00:00:00:02 with unknown destination port should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt, "eth2", reqpkt, display=Ethernet),
        "Ethernet frame destined for 30:00:00:00:00:02 should be flooded out eth1 and eth2")
        
    reqpkt = mk_pkt("20:00:00:00:00:11", "30:00:00:00:00:03", '192.168.1.103','172.16.42.3')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet),
        "Ethernet frame from 20:00:00:00:00:01 to 30:00:00:00:00:02 with unknown destination port should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt, "eth2", reqpkt, display=Ethernet),
        "Ethernet frame destined for 30:00:00:00:00:02 should be flooded out eth1 and eth2")
    
    reqpkt = mk_pkt("20:00:00:00:00:12", "30:00:00:00:00:03", '192.168.1.103','172.16.42.3')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet),
        "Ethernet frame from 20:00:00:00:00:01 to 30:00:00:00:00:02 with unknown destination port should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt, "eth2", reqpkt, display=Ethernet),
        "Ethernet frame destined for 30:00:00:00:00:02 should be flooded out eth1 and eth2")
        
    reqpkt = mk_pkt("20:00:00:00:00:13", "30:00:00:00:00:03", '192.168.1.103','172.16.42.3')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet),
        "Ethernet frame from 20:00:00:00:00:01 to 30:00:00:00:00:02 with unknown destination port should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt, "eth2", reqpkt, display=Ethernet),
        "Ethernet frame destined for 30:00:00:00:00:02 should be flooded out eth1 and eth2")
    return s

scenario = learning_switch_tests()
