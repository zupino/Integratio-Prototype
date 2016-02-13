#! /usr/bin/python

from scapy.all import *
from tester import *

# To be used when working on local interface l0
conf.L3socket = L3RawSocket

class TestComponent(object):
	
	def __init__(self):
		self.testServers=[]

	def jsonParse(self, file='test.json'):
		''' Function to be completed by raja for Issue #5 to parse a specific 
		json file and return as python dictionary.'''
		pass

	def createTestServer(self, jsonDict=None):
		''' Function calls the Tester Component defined in Tester.py'''
		tester = Tester(jsonDict)
	
	def run(self):
		''' Function which search for the list of json files in the specified 
		configuration folder and calls the jsonParse function in loops. This 
		is also part of Issue #5. '''
		pass


if __name__=='__main__':
	componentCreate = TestComponent()
	componentCreate.run()