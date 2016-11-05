#!/usr/bin/env python

import socket, sys, subprocess, argparse
from datetime import datetime
from scapy.all import *

def ip_scan(IP, args):
    if IP == "default":
        IP = "192.168.1.0/24"
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"), timeout=2 ) 
    ans.summary(lambda(s,r) : r.sprintf("%IP.src% %ARP.psrc%"))

def scan_tcp(ip):
  # Simple tries to complete a tcp connection with a port
  # Can often be blocked by firewalls especially if you are doing a portsweep
	try:
	  for port in range(1,1025):
	    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = s.connect_ex((ip, port))
	    if result == 0:
	      print "Port {}: 	 Open".format(port)
	      s.close()
	except KeyboardInterrupt:
	    print "Ctrl+C pressed"
	    sys.exit()
	except socket.gaierror:
	    print 'Hostname could not be resolved. Exiting'
	    sys.exit()
	except socket.error:
	    print "Couldn't connect to server"
	    sys.exit()


def scan_udp(ip):
  print 'udp scan'
  # UDP scans send a UDP packet to a port and listen for an ICMP packet stating the port is closed
  # if this packet is not received then either:
  #   1. The port is open
  #   2. The firewall filtered out the packet
  try:
    for port in range(1,1025):
      socket_recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
      socket_recv.settimeout(0.1)
      socket_recv.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
      socket_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      socket_send.sendto("Anyone Home?", (ip, port))
      #now listen for ICMP message saying port is closed
      # data, addr = None
      try:
        data, addr = socket_recv.recvfrom(1508)
        #print "Packet from %r: %r" % (addr,data)
        #print "Port {}: 	 Closed".format(port) 
      except socket.timeout:
      	print "Port {}: 	 Possibly Open".format(port)   
  except KeyboardInterrupt:
    print "You pressed Ctrl+C"
    sys.exit()

def syn_scan(ip):
  SYN_FLAG = 2

  syn_pkt = IP(dst=ip)/TCP(flags=SYN_FLAG, dport=range(1,1025), sport=RandShort())
  try:
    ans, unans = sr(syn_pkt, verbose=0)
    ans.summary(lfilter = lambda (s,r): r.sprintf("%TCP.flags%") == "SA",prn=lambda(s,r):r.sprintf("%TCP.sport% \t open"))
  except KeyboardInterrupt:
    print "You pressed ctrl-C"
    sys.exit()

def fin_scan(ip):
  #will not work on microsoft OS's as they do not implement proper TCP behaviour
  #open ports are supposed to ignore a fin packet from a non-connected source
  #closed ports reply with a RST packet
  FIN_FLAG = 1
  fin_pkt = IP(dst=ip) / TCP(flags=FIN_FLAG, dport=range(1, 1024), sport=RandShort())
  try:
    ans, unans = sr(fin_pkt, timeout=0.1, verbose = 0)
    for s in unans:
      print "Port {}:	Open".format(s[TCP].dport)
  except KeyboardInterrupt:
    print "You pressed ctrl-C"
    sys.exit()


def main():
    #IP   = socket.gethostbyname(addr)
    t1 = datetime.now()
    parser = argparse.ArgumentParser(description="Scan a given port with a chosen method")
    parser.add_argument('-i', action='store_true', help='Scans a given subnet or default subnet if "default" given')
    parser.add_argument('-s', action='store_true', help='A TCP scan, completes 3-way handshake then disconnects.')
    parser.add_argument('-d', action='store_true', help='A UDP port scan, closed UDP ports reply with an ICMP error packet.')
    parser.add_argument('-y', action='store_true', help='A SYN scan, an open port will acknowledge the packet.')
    parser.add_argument('-f', action='store_true', help='A FIN scan, open ports will ignore this packet except on Windows.')
    parser.add_argument('ip_address', metavar='IP', help='target IP address')
    args = parser.parse_args()
    
    IP = socket.gethostbyname(args.ip_address)
    if args.i:
        ip_scan(IP, args)
    if args.s:
        scan_tcp(IP)
    elif args.d:
        scan_udp(IP)
    elif args.y:
        syn_scan(IP)
    elif args.f:
        fin_scan(IP)
    t2 = datetime.now()
    total =  t2 - t1

    # Printing the information to screen
    print 'Scanning Completed in: ', total

main()
