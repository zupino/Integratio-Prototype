#!/usr/bin/python

from scapy.all import *
import time
import sys

print conf.iface

conf.L3socket = L3RawSocket

class TCPConnection(object):
	def __init__(self, ad, po):
		self.add = ad
		self.port = po
		self.t = TCP_client.tcplink(Raw, self.add, self.port)
		time.sleep(2)	
	def sendInt(self, payload):
		self.t.send(payload)
	
	def waitForConnection(self, timeout, period):
		mustend = time.time() + timeout
		while time.time() < mustend:
			if (self.t) and (self.t.atmt.state.state == 'ESTABLISHED'): return True
			time.sleep(period)
		return False


conn = TCPConnection("127.0.0.1", 8091)

# Just a try for a waiting function
print "\n\t[DEBUG] Entering the check status function"
mustend = time.time() + 5
while time.time() < mustend:
	if conn.t.atmt.state.state == 'ESTABLISHED': 
		print "\t[DEBUG] Now the connection is established, leaving the waiting loop"
		break	
	else:
		print "\t[DEBUG] not established yet. Status is: " . conn.t.atmt.state.state
		time.sleep(0.001)



conn.sendInt("GET / HTTP/1.0\r\n\r\n")
time.sleep(2)
conn.t.close()
time.sleep(1)
#tcp = TCP_client.tcplink(Raw, "www.google.com", 11111)
#tcp.send("ginger")

# I insert the code to close the stdout and stderr to avoid the "sys.excepthook is missing" error with Scapy 2.2.0

