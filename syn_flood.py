#!/usr/bin/env python3
import random
import argparse
import logging

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import IP, TCP, sniff, conf

conf.verb = 0

# IP addresses --> all Hosts on the LAN
NET_MAP = []

def net_map(ip):
	"""
	Get all IP hosts that are alive and in same LAN as 'ip'.
	Resolve MAC addresses. 
	"""

def tcp_syn_flood(ip, port, n=1000):
	"""
	Through this attack, attackers can flood the victim’s queue that is used for half-opened connections,
	i.e. the connections that has finished SYN, SYN-ACK, but has not yet got a final ACK back. 
	When this queue is full, the victim cannot take any more connection.
	"""

	for i in range(n):
		pass

def parse_args(argv):
	"""
	Parse Command Line Arguments
	"""
	pass

if __name__ == '__main__':
	pass