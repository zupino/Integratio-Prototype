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

#
#
#   ##         #
#   # #        #
#   #  #  ###  ###  #   #  ###
#   #  #  ##   #  # #   # #   #
#   ###   ###  ###   ###   ###
#                            #
#                          # #
#                           #
#
#   Load the script in scapy and manually create the
#   TCZee object
#
#      log_interactive.setLevel(1)
#      t = tcz.TCZee(80, debug=x)
#      t.run()
#
#
#   HTTZ branch with new comments, no merged with master
#
from scapy.all import *
# from tcz import TCPConnection
import time
import sys
import signal
from functools import wraps
# Just a small utility to get from system the ip of a specific network interface
import socket
import fcntl
import struct

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

# get_ip_address('eth0')
# '38.113.228.130'



conf.L3socket = L3RawSocket

class TCZee(Automaton):
	def parse_args(self, sport=80, Tstate=[], category=None, parameter=None, nCond=None, **kargs):
		# DEBUG	
		#print "[DEBUG] Starting processing parameters"	
		Automaton.parse_args(self, **kargs)
		self.sport = sport
		self.dport = 0
		self.responseReady = 0
		self.synAckReady = 0
		self.myIp = 0
		# TODO	Keep track of last processed HTTP request, to 
		# 	avoid problems with retransmission. Need to be refactored and cleaned up
		self.lastHttpRequest = ""
		# recv and send buffer to be used by the external     httz component
		self.recv = ""
		self.toSend = ""
		self.Tstate=Tstate
		self.category=category
		self.parameter=parameter
		self.nCond=nCond

                # We are assuming here that IntegratioWebServer is listening on wlan0 interface
                try:
                        # Just temporary to check on eth0 interface
			#self.myIp = get_ip_address('wlan0')
			self.myIp = 0
			#print "MyIP address: " + str(self.myIp)
                except IOError:
                        self.myIp = 0
                        #print "\t[WARNING] 'wlan0' interface not available, not possible to get local IP address for master filter."
                        pass

		
	def master_filter(self, pkt):
		
		# Checking the current state of the Automaton and checking the current state to conditions to be
		# executed. If all conditions in the config files are tested it would stop the thread
		if self.nCond<=0:
			print "Current state:%s"%(self.state.state)
			print "Pushing the Automaton to final state"
			self.state.state=self.state.final
			return
			
        
		if self.state.state == self.Tstate[0] and self.category=='time':
			print "In master filter :: going to sleep for %d"%(self.parameter)
			time.sleep(self.parameter)
			self.nCond=self.nCond-1

        
		# If I could retrieve my ip address, I use it in master filter, otherwise I do not use it.
		if self.myIp == 0:
			# print "myIp is not defined"
			return 	( IP in pkt and TCP in pkt \
				and pkt[TCP].dport == self.sport \
				)
		else:
		# print "myIp is defined"
			return 	( IP in pkt and TCP in pkt \
					and pkt[IP].dst == self.myIp \
					and pkt[TCP].dport == self.sport \
			)

	# Definition of the method to access the recv buffer
	# this is intented to be called by the httz component
	def receive(self):
		# This method will consume the available buffer
		ret = self.recv
		self.recv = ""
		return ret

	# Definition of the method to check the content of the recv buffer without
	# consuming it. I should refer to the system socket implementation to check
	# the proper naming. This does not relly have an equivalent in SOCK_STREAM
	# C socket programming
	def read(self):
		return self.recv

	# Definition of the operation to let external component httz write in 
	# the send buffer
	def write(self, data):
		self.toSend = data
		# There is a send_response action binded to the ESTABLISHED state
		# that should be re-used here. I'll do later TODO NEXT!
		# we can just copy that code here or in the next method send()
		
		# I prepare the responseReady flag to notify that a response is available
		# in the buffer to be sent. 
		# The actual send is done by the method send_response (not an action anymore)
		self.responseReady == 1


	# This is not an action of the receive_pshAck condition, but a simple method that should be explicitly called
        # for example by the external httz component

	# @ATMT.action(receive_pshAck)
	def send_response(self):
	# Not sure if it makes much sense to have a method to just send, without being clear what is sent
	# but theoretically we should reach this point only via the receive_pshAck condition (and if the flag 
	# 'responseReady' is set)

		if self.responseReady == 1:
			self.l3[TCP].payload = self.toSend 
			self.l3[TCP].flags = 'A'
			self.last_packet = self.l3
			self.send(self.last_packet)
			# DEBUG
			#print "\t\t[DEBUG][ESTABLISHED] Sent the RESPONSE! We are in the action now, but the condition has a transiction back to ESTABLISHED. Sent: " + self.last_packet.summary()
			self.responseReady = 0
			# TODO  Here I am 'hardcoding' the update of the local SEQ number, after sending the response.
			#       When I am using nc as client, after sending the request, a FIN-ACK is immediately send
			#       and the ACK value here is still 1 (because response form TCZee is not received yet).
			#       So TCZee get a FIN-ACK that does not ACK the HTTP Response.
			#       At this point, the send_finAck is triggered and TCZee send the FIN-ACK to close the connection
			#       but the TCZee SEQ number is wrong as it does not consider the ACKed response from client.
			#       I believe that also in case of a client that does not immediately send the FIN-ACK without ACKing
			#       the response, the correct value should be copied from pkt. Let's see. 

			self.l3[TCP].seq += len(self.last_packet[TCP].payload)
			self.l3[TCP].payload = ""
		else:
			# nuffin'
			self.responseReady = 0
	
	# BEGIN
	@ATMT.state(initial=1)
	def BEGIN(self):
		self.l3 = IP()/TCP()
		#self.lastHttpRequest = ""
		raise  self.LISTEN()
	
	# LISTEN
	@ATMT.state()
	def LISTEN(self):
		pass

	@ATMT.receive_condition(LISTEN)
	def receive_syn(self, pkt):
		#DEBUG	
		#print "\t[DEBUG][LISTEN] Received this packet: " + pkt.summary()

		# Checking if what I got is a SYN
		if (TCP in pkt and (pkt[TCP].flags == 0x02)):
			# DEBUG
			#print "\t\t[DEBUG][LISTEN] Inside the if (TCP SYN received)"
			self.l3[IP].dst = pkt[IP].src
			self.l3[TCP].seq = 124578
			self.l3[TCP].ack = pkt[TCP].seq + 1
			self.l3[TCP].dport = pkt[TCP].sport

			# used in the receive conditions over all the program
			self.dport = self.l3[TCP].dport

			self.l3[TCP].sport = pkt[TCP].dport 
			# self.l3[TCP].flags = 'SA'
			# DEBUG
			#print "\t\t[DEBUG][LISTEN] All value from pkt copied"

			# Changed 01.11.2015 I keep here the raise to change state, but I moved the call to send() in
			# the related action, so also the state diagram will look ok.
			
			self.synAckReady = 1
			raise self.SYNACK_SENT()
		# DEBUG
		#else:	
		#	print "\t[DEBUG][LISTEN] Whatever I got was NOT a SYN. Here the packet: " + pkt.summary()
			# Redundant, but to remember we have this flag
		#	self.synAckReady = 0
		#	pass

	@ATMT.action(receive_syn)
	def send_synack(self):
		# DEBUG
		#print "\t\t[DEBUG][LISTEN] running the action send_synack"
		if self.synAckReady:
			self.l3[TCP].flags = 'SA'
			self.last_packet = self.l3
			self.send(self.last_packet)
			self.synAckReady = 0

			#self.lastHttpRequest = ""
			# DEBUG
			#print "\t\t[DEBUG][LISTEN] SYN ACK sent (synAckReady flag is set): " + self.last_packet.summary()
		else:
			#print "\t\t[DEBUG][LISTEN] synAckReady flag NOT set, we received NOT A SYN: " + pkt.summary()
			self.synAckReady = 0
			pass
	
	# I do not need a timeout for the LISTEN state as anyway it would keep listen until something (a SYN) is received.

	# SYNACK_SENT
	@ATMT.state()
	def SYNACK_SENT(self):
		#self.lastHttpRequest = ""
		#DEBUG
		#print "[DEBUG][SYNACK_SENT] Entering now"
		pass

	@ATMT.receive_condition(SYNACK_SENT)
	def receive_ackForSyn(self, pkt):
		# DEBUG
		#print "[DEBUG][SYNACK_SENT] Packet received"
		
		# Check if I get an ACK (0x10)
		# TODO 	A check on received pkt ACK and SEQ number would make sense, to avoid any ACK to trigger this 
		# 	condition
		# -->	For the moment I add a check on the pkt source port, so basically I am making the engine handling 1 TCP STREAM
		#	per time, that is not necessarly a bad think. This will avoid also that re-transmitted packet from other stream
		#	to mess-up the status of the server

		if TCP in pkt and (pkt[TCP].sport == self.dport) and (pkt[TCP].flags & 0x10):
			self.l3[TCP].seq = pkt[TCP].ack
			self.l3[TCP].ack = pkt[TCP].seq
			# DEBUG
			#print "\t[DEBUG] [SYNACK_SENT] Received packet is a ACK, going to ESTABLISHED"
			raise self.ESTABLISHED()
		else:
			# Some other packet is received, not a ACK for the SYN/ACK, ignore and do nothing
			#print "\t\t[DEBUG][SYNACK_SENT] Some other packet than a ACK received, ignoring and doing nuffin': " + pkt.summary()
			pass
			# raise self.SYNACK_SENT(pkt)

	# Timeout: if I do not receive the ACK after 5 seconds sending the SYN ACK, then I go back to LISTEN
	@ATMT.timeout(SYNACK_SENT, 5)
	def timeoutSynAckSent(self):
		# DEBUG 
		#print "\t\t[DEBUG][SYNACK_SENT] We sent the SYN ACK but not received any ACK yet, timer expired --> back to LISTEN"
		raise self.LISTEN()


	@ATMT.state()
	def ESTABLISHED(self):
		#self.lastHttpRequest = ""
		# DEBUG
		#print "[DEBUG][ESTABLISHED] Entering state"
		pass

	# Let's try to separate all these cases in separate conditions, 
	# code should look better and TCZee.graph() would return a meaningful state chart diagram

	# in ESTABLISHED recv() FIN/ACK
	@ATMT.receive_condition(ESTABLISHED)
	def receive_finAck(self, pkt):
		# DEBUG
		#print "\t[DEBUG][ESTABLISHED] entering established_receive_data() condition" 
		
		# Check if the packet we got is a FIN/ACK 
		# TODO 	Make sure that in case of passive close we 
		# 	are expecting a FIN/ACK
		# TODO 	It seems like if we make the & on 0x11, and ACK is enough to make it pass
		# 	so we try to separate the checks on each flags. Check if this is true.
		#	One issue: it seems like the last ACK from the 3-way HS is somehow
		#	considered here also while running, even if I would expect this to
		#	already be consumed at this point in time
		
		if TCP in pkt and (pkt[TCP].sport == self.dport) and (pkt[TCP].flags == 0x11):
			# TODO 	here we will put the transition to the state CLOSING 
			# 	and the related action(CLOSING) will send the FIN/ACK and 
			#	keep track of the sequence and ack numbers correctly. Check 
			# 	also TCP state diagram
			
			# DEBUG
			#print "\t\t[DEBUG][ESTABLISHED] in the condition, pkt is a FIN so I raise CLOSING state (condition): " + pkt.summary() + ". pkt port: "  + str(pkt[TCP].sport) + ", curr port: " + str(self.dport)
			# Adjusting the seq and ack, in case of handshake and closing, there is an
			# 
			# To consider the case detailed in the comment of the send_response, I assign to the local SEQ the pkt[TCP].ack only if it is strictly 
			# bigger than the current SEQ value.
			
			if( pkt[TCP].ack > self.l3[TCP].seq ):
				self.l3[TCP].seq = pkt[TCP].ack
			self.l3[TCP].ack = pkt[TCP].seq + 1
			# EXTRADEBUG
			print "\t\t[EXTRADEBUG][ESTABLISHED] Received FIN-ACK: " + pkt.summary() + ". pkt[TCP].seq: " + str(pkt[TCP].seq) + " | pkt[TCP].ack: " + str(pkt[TCP].ack)
			#self.lastHttpRequest = ""

			raise self.CLOSING()

	# The action before transition to CLOSING is the send of FIN/ACK, that was before 
	# part of the receive_finAck condition

	@ATMT.action(receive_finAck)
	def send_finAck(self):
		#print "\t\t[DEBUG][ESTABLISHED] Moving to CLOSING state, sending FIN/ACK (action)"
		self.l3[TCP].flags = 'FA'
                self.last_packet = self.l3
                self.send(self.last_packet)

	
	# Second condition based on split of ESTABLISHED receive data cases
	# in ESTABLISHED recv() PSH/ACK
	@ATMT.receive_condition(ESTABLISHED)
	def receive_pshAck(self, pkt):

		# check if the received packet is a PSH/ACK 0x18
		# TODO 	EPIC this will need to consider also the case of HTTP requests splitted over
		#	multiple TCP segments, for the moment we assume request fits in one segment.
		#
		#	NOTES: 	HTTP Request can be
		#
		#			- Without a body: The request is completed when you have 2 consecutives new lines
		#			  0x0A 0x0D 0x0A 0x0D (but we should gracefully consider also LR only			
		#
		#			- With a body: In this case, the request terminate
		#				- when the number of char indicated in Content-length is reached
		#				- according to the logic to handle the Chunked request
		#
		 
		# TODO 	Assuming that the HTTP data will be always contained in a TCP segment flagged as
		# httz	PSH/ACK, this is not necessarly true. In general all the data that arrives
		#	should be copied in the recv buffer
		
		if TCP in pkt and (pkt[TCP].sport == self.dport) and (pkt[TCP].flags == 0x18):
			# DEBUG 
			#print "\t\t[DEBUG][ESTABLISHED] in the condition established_received_data, pkt is a PSH/ACK"
			
			# TODO 	As of now, we are just assuming that the content of the TCP load
			#	is an HTTP request, this might be also something else in a more advanced version
			#	but if we need to start from somewhere, that's for sure HTTP(S)
			
			# TODO	Adding here a check to verify if we are already processing the request just
			#	received. Maybe we can go to another state (something like PROCESSING_REQUEST)
			# 	to avoid that retransmission from the client mess-up the ACK counting. We clean 
			# 	this buffer when timeout, because I might want to make 2 consecutive requests for
			#	the same resource.

			if pkt[TCP].load : #and (pkt[TCP].load != self.lastHttpRequest) : 
		
				# Adding the received load to the recv buffer
				self.recv += pkt[TCP].load
				
				self.l3[TCP].seq = pkt[TCP].ack
				self.l3[TCP].ack += len(pkt[TCP].load)
				# 
				#print "\t\t[DEBUG][ESTABLISHED] This is the content of the PSH/ACK packet just received: " + pkt[TCP].load


			# If received pkt has no load OR if the HTTP request is already received
			# in this case I do nothing
			else:
				# DEBUG
				#print "\t\t[DEBUG][ESTABLISHED] pkt either has no load or the request is already in process. Pkt: " + pkt.summary()
				#print "\t\t[DEBUG][ESTABLISHED] content of current local buffer: " + self.lastHttpRequest
				pass
				
			# self.l3[TCP].seq = pkt[TCP].ack
			
			# Still in the assumption that whatever PSH/ACK TCP packet we receive from the client
			# will actually contains an HTTP request. Also, I am assuming that all the sizes goes 
			# automatically with Scapy magic
			# TODO seems like sending the ACK for the request and the response in the same TCP segment
			# is not ok, trying to send them separatelly
			# self.l3[TCP] = httpResponse
			
			# ??? 	it is still not clear what is better in such a situation: put here the send() call
			# 	or put it in the action related to this state? Question arises because based on
			# 	content of the pkt I might need different actions triggered, without the change of state.
			#	Does this even make sense? I send here for the moment as I need to send the ACK but 
			#	I do not need to change the state. This is different to the previous if case, for example,
			#	where also the state change.
			#
			# !!!	For the moment the best answer to this is that we should have a different ATMT.receive_condition 
			#	for each case of the if, and send the response packet in the action of each condition.
			#	From code execution point of view maybe no difference in the 2 approaches, but thi separation
			#	allow to generate automatically a much more clear state diagram with TCZee.graph()

                	# self.l3 = self.l3/httpResponse
			# self.responseReady = 1
			# Just want to move the send() call into the related ATMT.action, just to keep 
			# the code clean and according to state machine formalism

			raise self.ESTABLISHED()
		else:
			self.responseReady = 0
			# DEBUG
			#print "\t\t[DEBUG][ESTABLISHED] We receive something that is not a PSH/ACK, so we keep flag to 0 and pass (should stay in ESTABLISHED): " + pkt.summary()
			pass

	
	# This is not an action of the receive_pshAck condition, but a simple method that should be explicitly called
	# for example by the external httz component

	# @ATMT.action(receive_pshAck)
	def send_response(self):
		# Not sure if it makes much sense to have a method to just send, without being clear what is sent
		# but theoretically we should reach this point only via the receive_pshAck condition (and if the flag 
		# 'responseReady' is set)
		if self.responseReady == 1:
			self.l3[TCP].flags = 'A'
			self.last_packet = self.l3
			self.send(self.last_packet)
			# DEBUG
			#print "\t\t[DEBUG][ESTABLISHED] Sent the RESPONSE! We are in the action now, but the condition has a transiction back to ESTABLISHED. Sent: " + self.last_packet.summary()
			self.responseReady = 0
			
			# TODO 	Here I am 'hardcoding' the update of the local SEQ number, after sending the response.
			#	When I am using nc as client, after sending the request, a FIN-ACK is immediately send
			#	and the ACK value here is still 1 (because response form TCZee is not received yet).
			#	So TCZee get a FIN-ACK that does not ACK the HTTP Response.
			#	At this point, the send_finAck is triggered and TCZee send the FIN-ACK to close the connection
			#	but the TCZee SEQ number is wrong as it does not consider the ACKed response from client.
			#	I believe that also in case of a client that does not immediately send the FIN-ACK without ACKing
			#	the response, the correct value should be copied from pkt. Let's see. 
			
			self.l3[TCP].seq += len(self.last_packet[TCP].payload)
			self.l3[TCP].payload = ""
		else:
			# nuffin'
			self.responseReady = 0

	# Pay attention to methos names, should not be called the same as in 
	# the condition for the LISTEN state!!!

	# in ESTABLISHED recv() a SYN (basically client want to start a new tcp stream)
	@ATMT.receive_condition(ESTABLISHED)	
	def receive_synInEstablished(self, pkt):
		# For this receive condition I do not check the source port, because if I get a SYN
		# while in ESTABLISHED, it might be the client trying to open a new tcp strem
		# TODO 	Check if in this multi tcp stream handling approach is correct or if we should
		#	simply put a timer for the ESTABLISHED state and let the state machine going back to LISTEN after sending the response
		#	We should check the "Keep Alive" header...

		if TCP in pkt and (pkt[TCP].flags == 0x02) :
			# DEBUG
			#print "\t\t[DEBUG][ESTABLISHED] We received a SYN while in ESTABLISHED"
			self.synAckReady = 1
			self.l3[TCP].seq = 0
			self.l3[TCP].ack = pkt[TCP].seq + 1

			# We have a new TCP stream!
			self.l3[TCP].dport = pkt[TCP].sport
			self.dport = pkt[TCP].sport

			self.l3[TCP].payload = ""
			raise self.SYNACK_SENT()

	@ATMT.action(receive_synInEstablished)
	def sendSyn_inEstablished(self):
		if self.synAckReady == 1:
			# DEBUG
	                #print "\t\t[DEBUG][ESTABLISHED] running the action send_synack"
        	        self.l3[TCP].flags = 'SA'
                        self.last_packet = self.l3
                        self.send(self.last_packet)
                        # DEBUG
                        #print "\t\t[DEBUG][ESTABLISHED] SYN ACK sent (synAckReady flag is set): " + self.last_packet.summary()
			self.synAckReady = 0
                else:
                        #print "\t\t[DEBUG][ESTABLISHED] synAckReady flag NOT set, we received NOT A SYN (we should not even be here): " + pkt.summary()
                        print ""
			pass

	
	@ATMT.receive_condition(ESTABLISHED)
	def receive_ackInEstablished(self, pkt):
		if TCP in pkt and (0x10 == pkt[TCP].flags):
			# DEBUG
			#print "\t\t[DEBUG][ESTABLISHED] Received an ACK (just ACK): " + pkt.summary()
			#print "\t\t[DEBUG][ESTABLISHED] Updating local TCP.seq: " + str(pkt[TCP].ack)
			# EXTREME DEBUG
			print "\t\t[EXTRADEBUG][ESTABLISHED] Packet recognized as ACK: " + pkt.summary() 
			self.l3[TCP].seq = pkt[TCP].ack
			raise self.ESTABLISHED()
		else:
			pass

        def timeoutClosing(ESTABLISHED, self):
                # DEBUG
                #print "\t\t[DEBUG][ESTABLISHED] Timeout is expired, no data received, going back to LISTEN"
                self.l3[TCP].ack = 0
                self.l3[TCP].seq = 0
                self.l3[TCP].payload = ""
                self.last_packet = self.l3

	@ATMT.state() # Final just for the moment to avoid the warning
	def CLOSING(self):
		#DEBUG 
		#print "[DEBUG] entering [CLOSING]"
		print ""
			
	@ATMT.receive_condition(CLOSING)
	def receive_ack_closing(self, pkt):
		# DEBUG
		#print "\t\t[DEBUG][CLOSING] Received a pkt in CLOSING state, if ACK then connection is close and we go back to LISTEN"
		#if TCP in pkt and (pkt[TCP].sport == self.dport) and (pkt[TCP].flags & 0x10):
		# DEBUG
		#print "\t\t[DEBUG][CLOSING] Confirmed CLOSED state by receiving ACK to our FIN ACK. Reset SEQ and ACK numbers and back to LISTEN"
		self.l3[TCP].ack = 0
		self.l3[TCP].seq = 0
		self.l3[TCP].payload = ""
		self.last_packet = self.l3
		raise self.LISTEN()
		#else:
		#	# something else received
		#	# DEBUG
		#	print "\t\t[DEBUG][CLOSING] We receive something that is not an ACK: " + pkt.summary()
		#	pass
	
	@ATMT.timeout(CLOSING, 5)
	def timeoutClosing(self):
		# DEBUG
		#print "\t\t[DEBUG][CLOSING] Timeout is expired, no ACK received, going back to LISTEN"
		self.l3[TCP].ack = 0
                self.l3[TCP].seq = 0
                self.l3[TCP].payload = ""
                self.last_packet = self.l3
                raise self.LISTEN()


	# The decorators are defined as the static methods to define in the
	# same scope to avoid overlapping scope while updating the tcpHeader
	# attribute for content type tests.
	@staticmethod
	def contentDecorator(func):
		@wraps(func)
		def wrapped(self, *args, **kwargs):
			print "Inside content Wrapper. calling method %s now..."%(func.__name__)
			self.tcpHeader = 'I updated the header.. Now :)'
			response = func(self, *args, **kwargs)
			return response
		return wrapped

	@staticmethod
	def timeDecorator(func):
		@wraps(func)
		def wrapped(self, *args, **kwargs):
			print "Inside time Wrapper. calling method %s now.."%(func.__name__)
			response = func(self, *args, **kwargs)
			time.sleep(self.delay)
			print "After Sleep for a delay of.. %d"%(self.delay)
			return response
		return wrapped
#TCZee.graph()
#t = TCZee(80)
#t.run()
