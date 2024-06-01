#!/usr/bin/env python2

import argparse
from scapy.all import * # using scapy module for siffing, sending, and receiving packets
from scapy.all import sr1
from scapy.all import TCP, UDP, IP, ARP

# Parse command line arguments
parser = argparse.ArgumentParser()
parser.add_argument('--interface')
parser.add_argument('--victim-ip')
parser.add_argument('--victim-ethernet')
parser.add_argument('--reflector-ip')
parser.add_argument('--reflector-ethernet')
args = parser.parse_args()

interface = args.interface
victim_ip = args.victim_ip
victim_ethernet = args.victim_ethernet
reflector_ip = args.reflector_ip
reflector_ethernet = args.reflector_ethernet 


def sniffer_packet():
    sniff(iface=interface, prn=sniff_packet_callBack,count =0) 

def sniff_packet_callBack(packet):
    if ARP in packet:

        # Naturally: Attacker --Connects--> Victim // Attacker says who has 10.0.0.3?
        if (packet[ARP].pdst == victim_ip): 
            # Script: Says 10.0.0.3 has  mac: ff:b2:bb:ee:aa:8f 
            victimReply = ARP(psrc= victim_ip,pdst = packet[ARP].psrc,op=2,hwsrc = victim_ethernet,hwdst=packet[ARP].hwdst)

            send(victimReply)
            return

        # Naturally: Attacker says who has 10.0.0.4
        if(packet[ARP].pdst == reflector_ip):
            # Script: Says 10.0.0.4 has mac: 38:45:E3:89:B5:56
            reflectorReply = ARP(psrc= reflector_ip,pdst = packet[ARP].psrc,op=2,hwsrc = reflector_ethernet,hwdst=packet[ARP].hwdst)

            send(reflectorReply)
            return

    # Handle IP, TCP and UDP
    elif IP in packet:

        if (packet[IP].dst == victim_ip): 

            ip_packet = packet.getlayer(IP) 

            ip_packet[IP].src , ip_packet[IP].dst = reflector_ip, packet[IP].src 

            del ip_packet[IP].chksum

            if TCP in ip_packet:

                del packet[TCP].chksum

            if UDP in ip_packet:

                del packet[UDP].chksum
            
            send(ip_packet) 

        if (packet[IP].dst == reflector_ip): 

            ip_packet = packet.getlayer(IP) 

            ip_packet[IP].src , ip_packet[IP].dst = victim_ip, packet[IP].src 
            del ip_packet[IP].chksum

            if TCP in ip_packet:

                del packet[TCP].chksum
            if UDP in ip_packet:

                del packet[UDP].chksum
            
            send(ip_packet) 

     
def main():
    
    # Start sniffing packets
    sniffer_packet()

    # Callback function to be applied
    sniff_packet_callBack()

if __name__== "__main__":
    main()
    











        
