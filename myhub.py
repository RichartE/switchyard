from switchyard.lib.userlib import *

def main(net):
    # add some informational text about ports on this device
    log_info ("Hub is starting up with these ports:")
    ether_addr = set()
    for port in net.ports():
        log_info ("{}: ethernet address {}".format(port.name, port.ethaddr))
        ether_addr.add(str(port.ethaddr))
    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except Shutdown:
            # got shutdown signal
            break
        except NoPackets:
            # try again...
            continue

        # chack the address to make sure that 
        # the packet is not addressed to the hub
        if str(packet[Ethernet].dst) in ether_addr:
            # drop packets destined for the hub
            continue
        
        # send the packet out all ports *except*
        # the one on which it arrived
        for port in net.ports():
            if port.name != input_port:
                print("port", port.name)
                net.send_packet(port.name, packet)
                

    # shutdown is the last thing we should do
    net.shutdown()