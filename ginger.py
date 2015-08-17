from scapy.all import *

conf.L3socket = L3RawSocket

class TCPConnection(object):
	def __init__(self, ad, po):
		self.add = ad
		self.port = po
		self.t = TCP_client.tcplink(Raw, self.add, self.port)
	def sendInt(self, payload):
		self.t.send(payload)

conn = TCPConnection("www.google.com", 80)
conn.sendInt("GET / HTTP/1.0\r\n\r\n")

#tcp = TCP_client.tcplink(Raw, "www.google.com", 11111)
#tcp.send("ginger")

# I insert the code to close the stdout and stderr to avoid the "sys.excepthook is missing" error with Scapy 2.2.0
try:
    sys.stdout.close()
except:
    pass
try:
    sys.stderr.close()
except:
    pass

