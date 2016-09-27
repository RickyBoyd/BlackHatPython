#!/usr/bin/env python

import sys
from scapy.all import *

def main():
  ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"),timeout=2)
  ans.summary(lambda (s,r): r.sprintf("%Ether.src% %ARP.psrc%") )

main()
