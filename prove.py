#! /usr/bin/python

# TCZee - Scapy-based TCP stack basic implementation for network testing 
# Copyright (C) 2015 Marco Zunino

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# A copy of the full GNU General Public License is available in 
# the LICENSE file in the root folder of the original projecti
# hosted on 'https://github.com/zupino/tcz'.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# This file is part of the Integratio Project, a complete system test solution
# designed to run on a portable development board (as Raspberry Pi, BeagleBone or similar)
# and to provide a platform for the Integratio Test Suite, a collection of test cases to stress
# IoT product client functionalities while in condition of networking error or other corner cases
# that would be extremely difficult to reproduce on the real environment.

# This file is designed to run on a modified version of the Raspian operative system.
# The Raspberry device act as WiFi Access Point, DNS server and Web Server,
# providing answer to the requests of the tested IoT product in such a way to
# stress the desired error condition.


from scapy.all import *
# from tcz import TCPConnection
import time

conf.L3socket = L3RawSocket

class TCZee(Automaton):
	def parse_args(self, sport=80, **kargs):
		# DEBUG	
		print "[DEBUG] Starting processing parameters"	
		Automaton.parse_args(self, **kargs)
		self.sport = sport
		self.dport = 0
	
	def master_filter(self, pkt):
	#	return 	( IP in pkt and pkt[IP].src == self.server and TCP in pkt \
		return 	( IP in pkt and TCP in pkt \
				and pkt[TCP].dport == self.sport \
			)

	# BEGIN
	@ATMT.state(initial=1)
	def BEGIN(self):
		self.l3 = IP()/TCP()
		raise  self.LISTEN()
	
	# LISTEN
	@ATMT.state()
	def LISTEN(self):
		pass

	@ATMT.receive_condition(LISTEN)
	def receive_data(self, pkt):
		#DEBUG	
		print "\t[DEBUG] Entering in the receive_data method"

		# Checking if what I got is a SYN
		if (TCP in pkt and (pkt[TCP].flags & 0x02)):
			# DEBUG
			print "\t\t[DEBUG] Inside the if (TCP SYN received)"
			self.l3[IP].dst = pkt[IP].src
			self.l3[TCP].seq = pkt[TCP].ack
			self.l3[TCP].ack = pkt[TCP].seq + 1
			self.l3[TCP].dport = pkt[TCP].sport
			self.l3[TCP].sport = pkt[TCP].dport 
			self.l3[TCP].flags = 'SA'
			# DEBUG
			print "\t\t[DEBUG] All value from pkt copied"
			raise self.SYN_RECEIVED(pkt)
		# DEBUG
		print "\t[DEBUG] Whatever I got was not a SYN. Here the packet: " + pkt.summary()
		pass

	@ATMT.action(receive_data)
	def send_synack(self):
		# DEBUG
		print "[DEBUG] running the action send_synack"
		self.last_packet = self.l3
		self.send(self.last_packet)
		# DEBUG
		print "[DEBUG] SYN ACK sent: " + self.last_packet.summary()

	# SYN_RECEIVED
	@ATMT.state()
	def SYN_RECEIVED(self, pkt):
		#DEBUG
		print "[DEBUG] Entering now in state SYN_RECEIVED"
		pass

	@ATMT.receive_condition(SYN_RECEIVED)
	def receive_ackForSyn(self, pkt):
		# DEBUG
		print "[DEBUG] Receive condition on SYN_RECEIVED state"
		# Check if I get an ACK (0x10)
		if TCP in pkt and (pkt[TCP].flags & 0x10):
			self.l3[TCP].seq = pkt[TCP].ack
			self.l3[TCP].ack = pkt[TCP].seq
			raise self.ESTABLISHED()
		raise self.SYN_RECEIVED(pkt)

	@ATMT.state()
	def ESTABLISHED(self):
		# DEBUG
		print "[DEBUG] Just reached ESTABLISHED state! Ready to get a request!"

TCZee.graph()
#t = TCZee(80, debug=5)
#t.run()
