#! /usr/bin/python

from scapy.all import *

conf.L3socket = L3RawSocket

# As a simple start, we listen for incoming packets on port 80
# this code will be included in the recv() condition of an automaton 
# in a final version

a = sniff(count=1, filter="tcp and port 80")

remotePort = a[0].sport
remoteAddr = a[0][IP].src
seqNr = a[0].seq
ackNr = a[0].seq+1

# Miss to give a value to the src IP address should be enough to enure that the 
# correct systme source IP is used
ip = IP(dst=remoteAddr)

# Prepare and send the SYN/ACK packet
tcp_sa = TCP(sport=80, dport=remotePort, flags="SA", seq=seqNr, ack=ackNr)
answer = sr1(ip/tcp_sa)

# Get the next HTTP TCP packet (expected with the request)
getHttp = sniff(filter="tcp and port 80", count=1, prn=lambda x:x.sprintf("{IP:%IP.src%: %TCP.dport%}") )

# Update ACK and SEQ (aasuming the entire request is fitting one packet TODO)
ackNr = ackNr + len(getHttp[0].load) 
seqNr = a[0].seq + 1

if len(getHttp[0].load) > 1: print getHttp[0].load

# Generate the custom response

html1 = "HTTP/1.1 200 OK\x0d\x0aServer: Integratio Test Server\x0d\x0aConnection: Keep-Alive\x0d\x0aContent-Type: text/html; charset=UTF-8\x0d\x0aContent-Length: 848\x0d\x0a\x0d\x0a<html><head><title>Integratio - M. Zunino 2014</title></head><body><h2><span style='font-family:georgia,serif;'>Integratio - HTTP Test Server</span></h2><p><p><span style='color:#800080;'><span style='font-size:14px;'><em><span style='font-family:georgia,serif;'>The Integration project is an Open Source project started in 2014 by Marco Zunino.&nbsp;<a href='https://github.com/zupino/tcz'>https://github.com/zupino/tcz</a></span></em></span></span></p><span style='font-family:georgia,serif;'>This is a&nbsp;<em>really simple, </em><a href='https://bitbucket.org/secdev/scapy/src'>Scapy</a>-based implementation of a HTTP Web Server. The scope of this tool is to provide a framework to test the client robustness to <strong>network delay</strong>, <strong>malformed response </strong>and <strong>error condition</strong>.</span></p></body></html>"

data1 = TCP(sport=80, dport=remotePort, flags="PA", seq=seqNr, ack=ackNr)

ackData1 = sr1(ip/data1/html1)

seqNr = ackData1.ack

close = TCP(sport=80, dport=remotePort, flags="FA", seq=seqNr, ack=ackNr)
finalFA = sr1(ip/close)

seqNr = finalFA.ack

finalAck = TCP(sport=80, dport=remotePort, flags="A", seq=close.seq, ack=close.ack)




