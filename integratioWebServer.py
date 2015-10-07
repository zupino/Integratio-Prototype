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
import sys

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



# Because it seems like the normal filter is not working in the sniff function
# (at least not when run in script), I will use lambda filters and use them
# using lambda filter, as far as I understood online, the filtering will happening inside
# scapy without any external tool (tcpdump), but performance will be affected

localIp = get_ip_address('wlan0')
filSyn = lambda (r): TCP in r and r[TCP].dport == 80 and (r[TCP].flags & 0x02) and r[IP].dst == localIp
filAck = lambda (r): TCP in r and r[TCP].dport == 80 and (r[TCP].flags & 0x10) and r[IP].dst == localIp
filPsh = lambda (r): TCP in r and r[TCP].dport == 80 and (r[TCP].flags & 0x08) and r[IP].dst == localIp
filFin = lambda (r): TCP in r and r[TCP].dport == 80 and (r[TCP].flags & 0x01) and r[IP].dst == localIp


# I want this to keep run in backgrouns, keep listening for incoming connection
while(1):

	try:
		print "[STARTUP] Starting again listening for incoming request..."
		# As a simple start, we listen for incoming packets on port 80
		# this code will be included in the recv() condition of an automaton 	
		# in a final version.
		# As a first refinement, I added a filter on checking only for SYN packets here

		a = sniff(count=1, iface="wlan0", lfilter=filSyn, timeout=30)

		# This is just to avoid that sniff accumulate too many packets for too long.
		# every 30 seconds if nothing happen, we start over the main while loop
		if a:
			print "[DEBUG] step 1 sniff (a): "
			a.summary()
			pass
		else: 
			continue

		remotePort = a[0].sport
		remoteAddr = a[0][IP].src
		seqNr = a[0].seq
		ackNr = a[0].seq+1

		# At least in interactive console, creating a IP() without specifying the source addr, 
		# will automatically use 127.0.0.1, so I think it is not a reliable way to get local IP
		# TODO Need to check further when running as system script
		ip = IP(dst=remoteAddr)
		
		# Prepare and send the SYN/ACK packet
		tcp_sa = TCP(sport=80, dport=remotePort, flags="SA", seq=seqNr, ack=ackNr)
		# Try to use the approach of using always sniff instead of sr1(), this allow to avoid infite loop
		send(ip/tcp_sa)
		answer = sniff(count=1, iface="wlan0", lfilter=filAck, timeout=10)
		if answer:
			print "[DEBUG] step 2 sniff (answer): " 
			answer.summary()
			pass
		else:
			continue

		
		# Get the next HTTP TCP packet (expected with the request)
		getHttp = sniff(count=1, iface="wlan0", lfilter=filPsh, timeout=10)
		if getHttp:
			print "[DEBUG] step 3 sniff (getHttp): " 
			getHttp.summary()
			pass
		else:
			continue

		# Update ACK and SEQ (assuming the entire request is fitting one packet TODO)
		ackNr = ackNr + len(getHttp[0].load) 
		seqNr = answer[0].ack

		if len(getHttp[0].load) > 1: print getHttp[0].load
		
		# Generate the custom response
		
		html1 = "HTTP/1.1 200 OK\x0d\x0aServer: Integratio Test Server\x0d\x0aConnection: Keep-Alive\x0d\x0aContent-Type: text/html; charset=UTF-8\x0d\x0aContent-Length: 848\x0d\x0a\x0d\x0a<html><head><title>Integratio - M. Zunino 2014</title></head><body><h2><span style='font-family:georgia,serif;'>Integratio - HTTP Test Server</span></h2><p><p><span style='color:#800080;'><span style='font-size:14px;'><em><span style='font-family:georgia,serif;'>The Integration project is an Open Source project started in 2014 by Marco Zunino.&nbsp;<a href='https://github.com/zupino/tcz'>https://github.com/zupino/tcz</a></span></em></span></span></p><span style='font-family:georgia,serif;'>This is a&nbsp;<em>really simple, </em><a href='https://bitbucket.org/secdev/scapy/src'>Scapy</a>-based implementation of a HTTP Web Server. The scope of this tool is to provide a framework to test the client robustness to <strong>network delay</strong>, <strong>malformed response </strong>and <strong>error condition</strong>.</span></p></body></html>"
		
		# Prepare and send HTTP response
		data1 = TCP(sport=80, dport=remotePort, flags="PA", seq=seqNr, ack=ackNr)
		send(ip/data1/html1)
		ackData1 = sniff(count=1, iface="wlan0", lfilter=filAck, timeout=10)
		if ackData1:
			print "[DEBUG] step 4 sniff (ackData1): " 
			ackData1.summary()
			pass
		else:
			continue
		
		# Prepare and send the FYN/ACK to gracefully close connection
		seqNr = ackData1[0].ack
		close = TCP(sport=80, dport=remotePort, flags="FA", seq=seqNr, ack=ackNr)
		send(ip/close)
		finalFA = sniff(count=1, iface="wlan0", lfilter=filFin, timeout=10)
		if finalFA:
			print "[DEBUG] step 5 sniff (finalFA): " 
			finalFA.summary()
			pass
		else:
			continue
		
		# Prepare and send the final ACK after receiveing the FIN/ACK also from client
		ackNr = finalFA[0].seq + 1
		seqNr = finalFA[0].ack
		finalAck = TCP(sport=80, dport=remotePort, flags='A', seq=close.seq, ack=close.ack)
		send(ip/finalAck)

	except (KeyboardInterrupt, SystemExit):
		exit()

	except AttributeError:
		if ackData1:
			print ackData1[0].summary()
		# send(ip/TCP(flags='R'))
		continue

	except Exception as ex:
		template = "An exception of type {0} occured. Arguments:\n\t{1!r}"
		message = template.format(type(ex).__name__, ex.args)
		print "\t[Exception] " + message

		# send(ip/TCP(flags='R'))
		continue

	else:
		print "A kind of strange and unknown error condition happened."
		# send(ip/TCP(flags='R'))
		continue

