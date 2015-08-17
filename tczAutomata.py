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

	def __init__(self, dAdd, dPort, sAdd = "312.23.43.2", sPort = 12354):
		self.srcIp = sAdd
		self.dstIp = dAdd
		self.srcPort = sPort
		self.dstPort = dPort
		
		self.currAck = 0
		self.currSeq = 111250

		# TODO what happen with self.srcPort???
		print "\n\t[DEBUG]  creating an instance of TCP_client."
		self.tcpAuto = TCP_client.tcplink(Raw, self.dstIp, self.dstPort)
		print "\n\t[DEBUG]  after instance creation"


		#print "\n\t[DEBUG]  Trying to send some data directly after creation, boia faust!!"
		#self.tcpAuto.send("Ginger11111")

	def sendt(self, payload):
		print "\n\t[DEBUG]  about to send the payload with the wrapper"
		self.tcpAuto.send(payload) 

# Try to use google address this tiem
#ginger = TCPConnection("216.58.209.100", 80)
#print "\t\n[DEBUG]  After completing call to create instance"

#ginger.sendt("Piciu")
#print "\t\n[DEBUG]  Dopo aver inviato i dati con il wrapper"

# Trying here to send directly without using the TCPConnection obkect
t = TCP_client.tcplink(Raw, "79.209.203.90", 31331)
t.send("Puttana di Eva!!!")


# [22.07.2015 M. Zunino] Interrupted here, this is not working, even if conf is correct and the RST packets are
# correctly blocked. In some cases nothing is sent at all, in other cases only the SYN is sent but no response
# from the listening instance of netcat.
# Itis a little strange because the exact same code run from the scapy interactive console works (but also this not
# always, so I believe it is some kind of general problem of the system, need to check (all was run as root)

# [12.08.2015] I think the problem can be related with the `conf` object, if I use directly the TCP_client object
# and try to send shit to "www.google.com", I see at least the DNS request and maybe also SYN, nothing happen if
# I try to send in any way on the local interface, regardless of the conf.L3socket settings.



# I insert the code to close the stdout and stderr to avoid the "sys.excepthook is missing" error with Scapy 2.2.0
try:
    sys.stdout.close()
except:
    pass
try:
    sys.stderr.close()
except:
    pass
