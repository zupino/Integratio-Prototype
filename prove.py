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
	def receive_syn(self, pkt):
		#DEBUG	
		print "\t[DEBUG] Entering in the receive_syn method"

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
			# I think it woudl more clear if I raise the next STATE in the action instead of the in the condition
			# TODO I keep the raise call here as it does not work in the action, understand why
			raise self.SYNACK_SENT(pkt)
		# DEBUG
		else:	
			print "\t[DEBUG] Whatever I got was not a SYN. Here the packet: " + pkt.summary()
			pass

	@ATMT.action(receive_syn)
	def send_synack(self):
		# DEBUG
		print "[DEBUG] running the action send_synack"
		self.last_packet = self.l3
		self.send(self.last_packet)
		# DEBUG
		print "[DEBUG] SYN ACK sent: " + self.last_packet.summary()

	# SYNACK_SENT
	@ATMT.state()
	def SYNACK_SENT(self, pkt):
		#DEBUG
		print "[DEBUG] [SYNACK_SENT] Entering now"
		pass

	@ATMT.receive_condition(SYNACK_SENT)
	def receive_ackForSyn(self, pkt):
		# DEBUG
		print "[DEBUG] [SYNACK_SENT] Packet received"
		# Check if I get an ACK (0x10)
		# TODO A check on received pkt ACK and SEQ number would make sense, to avoid any ACK to trigger this 
		# condition
		if TCP in pkt and (pkt[TCP].flags & 0x10):
			self.l3[TCP].seq = pkt[TCP].ack
			self.l3[TCP].ack = pkt[TCP].seq
			# DEBUG
			print "\t[DEBUG] [SYNACK_SENT] Received packet is a ACK, going to ESTABLISHED"
			raise self.ESTABLISHED()
		raise self.SYNACK_SENT(pkt)

	#@ATMT.action(receive_ackForSyn)
	#def moveToEstablished(self):
		# DEBUG
		#print "\t[DEBUG] TEMP: Just triggering the state change from an action"
		#raise self.ESTABLISHED()

	@ATMT.state()
	def ESTABLISHED(self):
		# DEBUG
		print "[DEBUG] [ESTABLISHED] Entering state"
		pass

	@ATMT.receive_condition(ESTABLISHED)
	def established_receive_data(self, pkt):
		# DEBUG
		print "\t[DEBUG] [ESTABLISHED] entering established_receive_data() condition" 
		
		# Check if the packet we got is a FIN/ACK 
		# TODO 	Make sure that in case of passive close we 
		# 	are expecting a FIN/ACK
		# TODO 	It seems like if we make the & on 0x11, and ACK is enough to make it pass
		# 	so we try to separate the checks on each flags. Check if this is true.
		#	One issue: it seems like the last ACK from the 3-way HS is somehow
		#	considered here also while running, even if I would expect this to
		#	already be consumed at this point in time
		
		if TCP in pkt and (pkt[TCP].flags & 0x10 and pkt[TCP].flags & 0x01):
			# TODO 	here we will put the transition to the state CLOSING 
			# 	and the related action(CLOSING) will send the FIN/ACK and 
			#	keep track of the sequence and ack numbers correctly. Check 
			# 	also TCP state diagram
			
			# DEBUG
			print "\t\t[DEBUG] in the condition, pkt is a FIN so I raise CLOSING state"
			print "\t\t[DEBUG] Content of pkt: " + pkt.summary()
			raise self.CLOSING()

		# check if the received packet is a PSH/ACK 0x18
		# TODO 	EPIC this will need to consider also the case of HTTP requests splitted over
		#	multiple TCP segments, for the moment we assume request fits in one segment
		elif TCP in pkt and (pkt[TCP].flags & 0x10 and pkt[TCP].flags & 0x08):
			# DEBUG 
			print "\t\t[DEBUG] in the condition established_received_data, pkt is a PSH/ACK"
			if pkt[TCP].load: 
				self.l3[TCP].ack += len(pkt[TCP].load)
			self.l3[TCP].seq = pkt[TCP].ack
			self.l3[TCP].flags = 'A'
			# TODO 	it is still not clear what is better in such a situation: put here the send() call
			# 	or put it in the action related to this state? Question arises because based on
			# 	content of the pkt I might need different actions triggered, without the change of state.
			#	Does this even make sense? I send here for the moment as I need to send the ACK but 
			#	I do not need to change the state. This is different to the previous if case, for example,
			#	where also the state change.
			# DEBUG
                	print "\t\t[DEBUG] [ESTABLISHED] Sending the ACK"
                	self.last_packet = self.l3
               	 	self.send(self.last_packet)
        	        # DEBUG
	                print "\t\t[DEBUG] [ESTABLISHED]  data ACK sent, back to ESTABLISHED now: " + self.last_packet.summary()	
			raise self.ESTABLISHED()
		else:
			# Default option (some strange packet, RST for example
			pass



	@ATMT.state(final=1) # Final just for the moment to avoid the warning
	def CLOSING(self):
		#DEBUG 
		print "[DEBUG] entering [CLOSING]"
		

		


#TCZee.graph()
#t = TCZee(80, debug=5)
# t.run()
