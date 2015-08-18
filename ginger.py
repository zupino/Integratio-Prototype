#!/usr/bin/python

from scapy.all import *
import time

print conf.iface

conf.L3socket = L3RawSocket

class TCPConnection(object):
	def __init__(self, ad, po):
		self.add = ad
		self.port = po
		self.t = TCP_client.tcplink(Raw, self.add, self.port)
	def sendInt(self, payload):
		self.t.send(payload)
	
print "\n\t[DEBUG] Creation of TCPConnection object"
conn = TCPConnection("127.0.0.1", 8090)
time.sleep(2)
print "\n\t[DEBUG] About to send the message to port 8090 on localhost"
conn.sendInt("GET / HTTP/1.0\r\n\r\n")
time.sleep(2)
conn.t.close()

#tcp = TCP_client.tcplink(Raw, "www.google.com", 11111)
#tcp.send("ginger")

# I insert the code to close the stdout and stderr to avoid the "sys.excepthook is missing" error with Scapy 2.2.0
