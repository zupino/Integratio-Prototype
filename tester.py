from scapy.all import *
from lib.tcz import TCZee
from scapy.all import Automaton
from functools import wraps

import copy
import time


# To be used when working on local interface l0
#conf.L3socket = L3RawSocket
sys.path.append('.')

#log_scapy = logging.getLogger("scapy")
#console_handler = logging.StreamHandler()
#console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
#log_scapy.addHandler(console_handler)
#log_runtime = logging.getLogger("scapy.runtime")          # logs at runtime
#log_runtime.addFilter(ScapyFreqFilter())
#log_interactive = logging.getLogger("scapy.interactive")  # logs in interactive functions
#log_loading = logging.getLogger("scapy.loading")          # logs when loading scapy

class Tester(object):
    
    def __init__(self, jsonDict={}):
        self.configRegistry=jsonDict
        # This is being added earlier as debug statement to check if the 
        # there is no change in the Automaton Flow. 
        # TCZee.graph()
    
    def runComponent(self):
        ''' Function which search for the list of json files in the specified 
        configuration folder and calls the jsonParse function in loops. This 
        is also part of Issue #5. '''
        for test_id, config in self.configRegistry.iteritems():
            print "Test started for %s"%(test_id)
            self.currentTest=TCZee(80,
                                   jsonConfig=config,
                                   debug=3)
            self.currentTest.run()
            print "Test completed for %s"%(test_id)
            

class ConfigExpert(object):
    
    def __init__(self):
        self.jsonRegistry={}
        self.jsonCopy={}

    def process(self, rawJson):
        ''' Here the raw Json data from the file is process to 
        create a nested json with the test id as the keys for the
        jsonRegistry'''
        
        self.jsonCopy = copy.deepcopy(rawJson)
        current_key=self.jsonCopy['testID']
        self.jsonRegistry[current_key]={}
        del self.jsonCopy['testID']
        self.jsonRegistry[current_key]=self.jsonCopy

        # TODO: the logic for the combining the multi-config file
        # for the same testID must be handled here.
        
    
    def getRegistry(self):
        return self.jsonRegistry
    
