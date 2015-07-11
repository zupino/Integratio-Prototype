#!/usr/bin/python

# TCZee - Scapy-based TCP stack basic implementation for network testing 
# Copyright (C) 2014 Marco Zunino

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation
 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# A copy of the full GNU General Public License is available in 
# the LICENSE file in the root folder of the original project.
 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 
# Since scapy live in userspace, kernel is not aware of the 
# packet sent, so when the other side will reply, the kernel
# will send RST as response to the unexpected packets.

# The following iptables rule workaround this problem
# by blocking the RST from the local machine

# iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 127.0.0.1 -j DROP


from scapy.all import *
import random 
import time

# in case this program is used in localhost we need to change the
# socket configuration with the following command
conf.L3socket=L3RawSocket



class TCPConnection(object):
	"""As far as I understand this is a comment :)
	"""
	# mandatory parameters are only destination address and port
	# TODO For some reason randint() restiruisce sempre lo stesso valore se chiamata in __init__
	# ma funziona bene se nel "main" la chiamo quando invoco il costruttore...
	def __init__(self, dAdd, dPort, sAdd = "127.0.0.1", sPort = random.randint(1024,65535)):
		self.srcIp = sAdd
		self.dstIp = dAdd
		self.srcPort = sPort
		self.dstPort = dPort
		
		self.currAck = 0
		self.currSeq = 150
		
		self.packetSent = 0
		self.packetReceived = 0
		
		self.dataSent = ""
		self.dataReceived = ""
		
		self.lastHttpResponse = ""
		
		# 'status' is 1 if connected
		# 0 if not connected
		self.status = 0
	
	# keep the 3way handshake in a separate method
	# I set default values for time between packets, number of retry and timeout after last packet sent
	def handshake(self, timeoutp=1, interp=0.1, retryp=2):
		syn = IP(dst=self.dstIp, src=self.srcIp)/TCP(dport=self.dstPort, sport=self.srcPort, seq=self.currSeq, flags='S')
		synAck = sr1(syn, retry=retryp, timeout=timeoutp, inter=interp)
		if(synAck):
			# DEBUG
			print "\n\t[INFO] SYN-ACK received from server, completing handshake\n"
			self.currAck = synAck[TCP].seq + 1
			# in this case +1 would have be the same
			self.currSeq = synAck[TCP].ack
			# here I send only the ACK, in some cases I might need to send the payload already in this packet
			# I modify and re-use the syn just because most field already filled in 
			syn[TCP].flags = 'A'
			syn[TCP].ack = self.currAck
			syn[TCP].seq = self.currSeq
			# just to make it look nicer, not even correct :)
			ack = syn
			# this time I need to retry
			send(ack, verbose=0)
			# change the state machine of this connection
			self.status = 1
		else:
			print "\n\t[ERR] No response from server, could not complete handshake :(.\n\tYou can try to increase the timeout (current value:", timeoutp, "sec)\n"
			sys.exit()
		
	def close(self, timeoutp=5, interp=2, retryp=5):
		# if the connection is already established, close it
		# DEBUG
		if self.status == 1:
			print "\n\t[INFO] Entering the close connection operation, connection is established, client sends a FIN\n"
			fin = IP(src=self.srcIp, dst=self.dstIp)/TCP(dport=self.dstPort, sport=self.srcPort, seq=self.currSeq, ack=self.currAck, flags='F')
			finAck = sr1(fin, inter=interp, retry=retryp, timeout=timeoutp)
			if(finAck):
				#DEBUG
				print "\n\t[INFO] FIN-ACK received from the server, proceeding with closing the connectionn\n"
				self.currAck = finAck[TCP].seq + 1
				# We need to increase our seq as I am about to send a last TCP packet
				self.currSeq = finAck[TCP].ack + 1
				# now I need to send back the ACK to complete the close
				fin[TCP].flags = 'A'
				fin[TCP].seq = self.currSeq
				fin[TCP].ack = self.currAck
				ack = fin
				send(ack, verbose=0)
				# change the state machine of this connection
				self.status = 0
	
	# single packet version, send and receive		
	def sr1(self, payload, timeoutp=1, retryp=2, interp=2):
		if self.status == 0:
			# not connected, we need the 3-way HS
			self.handshake(0.5)
		p = IP()/TCP()/payload
		p[IP].dst = self.dstIp
		p[IP].src = self.srcIp
		p[TCP].seq = self.currSeq
		p[TCP].ack = self.currAck
		p[TCP].sport = self.srcPort
		p[TCP].dport = self.dstPort
		p[TCP].flags = 'PA'
		# need to check carufully here, is only ACK is returned or if also response data is returned
		# if data is returned, it might be in several packet...
		# for the moment consider the normal case of ACK
		ack = sr1(p, timeout=timeoutp, retry=retryp, inter=interp)
		if(ack):
			self.currAck = ack[TCP].seq
			self.currSeq = ack[TCP].ack
		return ack

	# multi response packet version, send and receive
	def sr(self, payload, recPackets = 2):
		# flag is used for returning the value
		# if there is a response with paylod from server, will be returned
		# if not we return ""
		
		flag = 0
		if self.status == 0:
                        # not connected, we need the 3-way HS
                        self.handshake(0.5)
                
		p = IP()/TCP()/payload
                p[IP].dst = self.dstIp
                p[IP].src = self.srcIp
                p[TCP].seq = self.currSeq
                p[TCP].ack = self.currAck
                p[TCP].sport = self.srcPort
                p[TCP].dport = self.dstPort
                p[TCP].flags = 'PA'
                
		# This time we send the single packet and we have waiting for more 
		# than one packet as response, so we use sniff with count and filter
		# TODO maybe should be removed from production code if possible
		# TODO also share with french guy here: stackoverflow.com/questions/13647853/
		send(p, verbose=0)
		
		# as mentioned using a lambda filter
		# THIS DOES NOT WORK, try with normal BPF filter
		#lFilter = lambda (r): TCP in r and r[TCP].sport = self.dsstPort and r[IP].src = self.dstIp
		lFilter = "tcp port " + str( self.dstPort )
		# TODO consider adding a timeout
		# for the moment I considet a count=3 because I am expecting an ACK, then a PSH/ACK with the response and a FIN/ACK
		# to close the connection
		
		# DEBUG
		print "\n\t[DEBUG] About to start with sniff(), next 3 packets will be captured"
		ans = sniff(filter=lFilter, count=recPackets)
                print "\n\t[DEBUG] sniff() completed"
		for a in ans:
			self.currAck = a[TCP].seq
                        self.currSeq = a[TCP].ack
                	self.packetReceived = self.packetReceived + 1
			# Start to make a better check for HTTP Response
			# check if a TCP payload is there in the first place, God bless Python!
			# Having set the sniff() with the filter on TCP port, should be safe to assume TCP packet
			if a[TCP].payload:
				print "\n\t[INFO] Saving the HTTP response to the internal var 'self.lastHttpResponse'"
				self.lastHttpResponse = str( a[TCP].payload )
				self.dataReceived += str( a[TCP].payload )
				self.currAck =	a[TCP].seq + len( a[TCP].payload )			
				p[TCP].ack = self.currAck
				p[TCP].seq = self.currSeq
				p[TCP].flags = 'A'
				p[TCP].payload = ""
				send(p, verbose = 0)
				
	# TODO 	this is part of TCPConnection for the moment, but should be an external function or even better
	#	a method of a HTTPSession class that include a TCPConnection. Need to refactor a little here		
		
	def getHeaderValue(self, header, payload):
		# we search for the cookie called 'str' and we return the corresponding value
		# we assume that 'str' is the payload
		for s in payload.split("\r\n"):
			if header in s:
				# ritorno il valore pulito di eventuali spazi vuoti a sinistra
				return s.split(":")[1].lstrip()

