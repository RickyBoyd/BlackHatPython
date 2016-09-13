#!/usr/bin/env python

import socket, sys, subprocess
from datetime import datetime

def scan_tcp(ip):
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


addr = sys.argv[2]
IP   = socket.gethostbyname(addr)



t1 = datetime.now()

if sys.argv[1] == '-s':
	scan_tcp(IP)
elif sys.argv[1] == '-d':
	scan_udp(IP)

t2 = datetime.now()
total =  t2 - t1

# Printing the information to screen
print 'Scanning Completed in: ', total

