#!/usr/bin/python

# TCZee - Scapy-based TCP stack basic implementation for network testing 
# Copyright (C) 2014 Marco Zunino

# The main purpose of this library is to provide the base for a 
# complete internet testing tool that will allow to check network 
# stack on IoT products with special attention on 
#
#	- Error condition (reproduce delay, malformed packets, error conditions,
#	  application level error, protocol errors and so on)
#
#	- Standard compliance at transport layer (TCP selective ACK, TCP timestamps)	
#	  network layer (malformed packet, wrong chksum etc) and application layer 
#	  (HTTP special Headers mechanism, HTTP error, new features etc)
#	 
#	- Security check (verify product response to overflow due to unexpected values
#	  in the protocol field, DoS attack and other robstness testing)


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

# === Usage Notes ===
 
# Since scapy live in userspace, kernel is not aware of the 
# packet sent, so when the other side will reply, the kernel
# will send RST as response to the unexpected packets.

# The following iptables rule workaround this problem
# by blocking the RST from the local machine

# iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 127.0.0.1 -j DROP

# Another important point from the Scapy FAQ:
# in case this script is used locally (to try on a local environment
# the sequence first, for example) we need to comunicate to 
# Scapy that we want to use a PF_INET socket instead of a PF_PACKET

# conf.L3socket = L3RawSocket

from scapy.all import *
import time
import sys

conf.L3socket = L3RawSocket

class TCPConnection(object):
	def __init__(self, ad, po):
		self.add = ad
		self.port = po

		# TODO in the initialization phase we are also calling the ``tcplink()`` funtion
		# that actually starts the handshake with the other TCP endpoint.
		# This might not be the correct moment to do so, this should be in a 
		# different method so that we can also remove that ugly call to ``time.sleep(2)``
		
		self.t = TCP_client.tcplink(Raw, self.add, self.port)
		
		expire = time.time() + 5
		
		stateExists = 'self.t.atmt.state.state' in locals() or 'self.t.atmt.state.state' in globals() 
		while time.time() < expire:
                	if stateExists and elf.t.atmt.state.state == 'ESTABLISHED':
                                print "\n\t\t\t[DEUBG](init) Connection status is OK, let's send! Status: " + self.t.atmt.state.state
                                break
                        else:
                                if stateExists:
					print "\n\t\t\t[DEBUG](init) Connection not ready yet, another cycle. Status: " + self.t.atmt.state.state
				else:
					print "\n\t\t\t[DEBUG](init) Connection not ready yet, object creation not completed. Time passed: " + str( time.time() - expire ) 
                                time.sleep(0.001)
                #print "\n\t\t[DEBUG] Inside sendInt(), starting waiting for 4 seconds."
                #time.sleep(4)
		
	
	def sendInt(self, payload):
		# In this wrapper we also check if the status of the connection
		# is ESTABLISHED before actually send any data.
		
		# Wait for 3 seconds in case connection is not completed
	
		expire = time.time() + 3
		
		while time.time() < expire:
			if self.t.atmt.state.state == 'ESTABLISHED':
				print "\n\t\t\t[DEUBG](sendInt) Connection status is OK, let's send! Status: " + self.t.atmt.state.state
				break
			else:
				print "\n\t\t\t[DEBUG](sendInt) Connection not ready yet, another cycle. Status: " + self.t.atmt.state.state
				time.sleep(0.001)
		#print "\n\t\t[DEBUG] Inside sendInt(), starting waiting for 4 seconds."
		#time.sleep(4)
		print "\t\t[DEBUG] about to send payload."
		self.t.send(payload)
		
		expire = time.time() + 3
		while time.time() < expire:
                	if self.t.atmt.state.state == 'ESTABLISHED':
                                print "\n\t\t\t[DEUBG](sendInt) Connection status is OK, let's send! Status: " + self.t.atmt.state.state
                                break
                        else:
                                print "\n\t\t\t[DEBUG](sendInt) Connection not ready yet, another cycle. Status: " + self.t.atmt.state.state
                                time.sleep(0.001)
                #print "\n\t\t[DEBUG] Inside sendInt(), starting waiting for 4 seconds."
                #time.sleep(4)


