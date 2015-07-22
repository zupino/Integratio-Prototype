#! /usr/bin/python

# Since scapy live in userspace, kernel is not aware of the 
# packet sent, so when the other side will reply, the kernel
# will send RST as response to the unexpected packets.

# The following iptables rule workaround this problem
# by blocking the RST from the local machine

# iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 127.0.0.1 -j DROP


from scapy.all import *
import random 
import time

conf.L3socket=L3RawSocket

class TCPConnection(object):
	"""This implementation is different from the original one as it include an instance of TCP_client
	as implementaed by Scapy. The class is designed to extend the TCP_client Automata functionalities
	like for example keep control on the ACK sent as reply after receiving a packet, in this implementation
	is possible to delay or completely skip these packets """

	def __init__(self, dAdd, dPort, sAdd = "127.0.0.1", sPort = 12354):
		self.srcIp = sAdd
		self.dstIp = dAdd
		self.srcPort = sPort
		self.dstPort = dPort
		
		self.currAck = 0
		self.currSeq = 111250

		# TODO what happen with self.srcPort???
		self.tcpAuto = TCP_client.tcplink(Raw, self.srcIp, self.dstPort)


	def send(self, payload):
		self.tcpAuto.send(payload) 


ginger = TCPConnection("127.0.0.1", 6666)
ginger.tcpAuto.send("Piciu")

# [22.07.2015 M. Zunino] Interrupted here, this is not working, even if conf is correct and the RST packets are
# correctly blocked. In some cases nothing is sent at all, in other cases only the SYN is sent but no response
# from the listening instance of netcat.
# Itis a little strange because the exact same code run from the scapy interactive console works (but also this not
# always, so I believe it is some kind of general problem of the system, need to check (all was run as root)
