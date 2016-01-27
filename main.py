#! /usr/bin/python

from scapy.all import *
from tczDebug import TCZee

# To be used when working on local interface l0
conf.L3socket = L3RawSocket

# THIS is a pseudo-code scheleton and illustration of what we are targeting
# for the Integratio Framework.
# It is not supposed to run, nor to contain all the component in this single
# file, but just to show the main component of the Integratio Framework 
# and the communication among them.

# 1) 	The test files are read from JSON TestCases on the filesystem
# 	for this example the test case is a simple delay in establishing
# 	the TCP connection (send the SYN ACK is delayed)
#
#	[inside the main.py]
tester = Tester()
tester.newTestServer("testCase001.json")

# The file content is somethig like this
#
# testCase001.json:
# 	{
#		category : "time",
#		state :	"send_synAck".
#		parameters: 5
#		listeningPort: 80
#		listeningAddress: gingerino.com
#	}
#

# 2) 	Internally, the Tester is instantiating a new TestServer object
# 	that is composed by a TCZee and a HTTZee class. These object are
#	configured on the base of the content of the TestCase we are loading

#		[inside Tester.py]
	self.newTestServer(filename)
		self.testServers[last] = TestServer( self.readJson(filename) ) 

#		[inside TestServer.py]
		init(config)
			self.tcz = TCZee(config)
			# Eventually, but not in the example we are considering
			self.httz = HTTZee( config.parameters )
			# TODO Need to properly place the shared buffers between TCZ and HTTZ. Inside TestServer? Would make sense
			
# 3) 	The TCZee class need to setup itself based on the parameters read in the json file,
#	passed as 'config' parameters when TestServer initialize it 
		
#		[inside TCZee.py]
		init(config)
			self.category = config.category # 'time' in this example
			self.testCaseState = config.state 	# This parameter tells the TCZee instance at which step of the TCP state machine
								# the behavior described by the json TestCase need to be setup.
		# [...] The check below should be repeated for each state in the state machine.
		@Automata.state SYNACK_SENT:
			if self.testCaseCategory == "SYNACK_SENT":
				switch(	self.category ):
					case "time"
						# prepare the needed code to delay the transmission of the acket in this
						# specific state. Might be as simple as a time.sleep(config.parameter) here
					case "content"
						# in this specific example it does not really make sense to consider the content
						# case, as we are in TCZee and the content case should be related with the 
						# application layer payload, so in the HTTZee component.
					case "fuzzy"
						# as we might want to send the SYN/ACK fuzzed, we might simply fuzz the headers
						# using built-in Scapy support or provide more details in the config.parameter
						# section  
						# TODO 2 Need to define the structure for the 'parameter' section so that
						#	 it will make sense and possibly try to avoid un-expected format

# 4)	Now that the test server is correctly setup and ready, we run it from the main file
#	[inside main.py]

tester.runLastTest()

# From this moment on, there is a TestServer listening on the configured port, 
# that as soon as the client connects, will behave according to the TestCase
# description in the json file. In this concrete example, will simply
# wait 5 seconds before sending the response packet in the SYNACK_SENT state.
# TODO check the consistencie with the state names
# TODO prepare a TCZee state machine
# TODO check how to apply the use case of 'content' category with HTTZee()