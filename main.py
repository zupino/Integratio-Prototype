#! /usr/bin/python

from scapy.all import *
from tester import *

# To be used when working on local interface l0
conf.L3socket = L3RawSocket

if __name__=='__main__':
	componentCreate = Tester()
	componentCreate.run()