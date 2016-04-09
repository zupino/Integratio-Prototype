from scapy.all import *
from tcz.tczDebugApp1 import TCZee
from scapy.all import Automaton
from functools import wraps

import copy
import time


# To be used when working on local interface l0
conf.L3socket = L3RawSocket
sys.path.append('.')

log_scapy = logging.getLogger("scapy")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
log_scapy.addHandler(console_handler)
log_runtime = logging.getLogger("scapy.runtime")          # logs at runtime
log_runtime.addFilter(ScapyFreqFilter())
log_interactive = logging.getLogger("scapy.interactive")  # logs in interactive functions
log_loading = logging.getLogger("scapy.loading")          # logs when loading scapy


'''Approach for Test Server using the Meta classes.'''

class TesterApp1(object):
    
    def __init__(self, jsonDict=None):
        self.configRegistry=jsonDict  
        self.nCond=jsonDict['Nconditions'] 
        self.parameter=jsonDict['parameter']
        self.stateTest=[]
        self.stateTest.append(jsonDict['state'])
        self.category=jsonDict['category']
        self.currentTest=TCZee(80,
                               Tstate=self.stateTest,
                               category=self.category,
                               parameter=self.parameter,
                               nCond=self.nCond,
                               debug=3)
        TCZee.graph()
    
    def runComponent(self):
        ''' Function which search for the list of json files in the specified 
        configuration folder and calls the jsonParse function in loops. This 
        is also part of Issue #5. '''
        self.currentTest.run()
            
                

class ConfigExpertApp1(object):
    
    def __init__(self):
        self.json = {}
        self.json['category']=''
        self.json['parameter']=''

    def process(self, rawJson):
        ''' Here the raw Json data from the file is process to 
        match the processed json structure.'''
        
        self.json = copy.deepcopy(rawJson)
        
        # Since we know that for the time category the parameter 
        # is a delay. It is converted to an Integer Value.
        
        if 'time' in self.json['category']:
            self.json['parameter']=int(rawJson['parameter'])
            # Here currently trying to test the same config from the json file for 5 times
            # But must 
            self.json['Nconditions']=2
        return self.json
