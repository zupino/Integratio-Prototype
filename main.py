#! /usr/bin/python

from scapy.all import *
from tcz import TCPConnection
import time

conf.L3socket = L3RawSocket

t = TCPConnection("127.0.0.1", 8091)

t.sendInt("Ginger\n")
print "\t[DEBUG] just sent something"
