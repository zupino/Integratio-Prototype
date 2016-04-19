from scapy.all import *
from tcz.tczDebug import TCZee
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

class Tester(object):
    
    def __init__(self, jsonDict=None):
        self.configRegistry=jsonDict  
        self.nCond=jsonDict['Nconditions'] 
        self.parameter=jsonDict['parameter']
        self.state=[]
        self.state.append(jsonDict['state'])
        self.category=jsonDict['category']
        self.currentTest=TCZee(80, debug=3)
        self.preProcess()
        TCZee.graph()
    
    def preProcess(self):
        
        if self.category=='time':
            self.timePreprocess()
        elif self.category=='content':
            self.contentPreprocess()
        else:
            self.fuzzyPreprocess()
    
    def timePreprocess(self):

        for state, deco_function in self.currentTest.states.iteritems():
                if state == self.state[0]:
                    self.currentTest.add_interception_points(state)

    def contentPreprocess(self):
        pass
    
    def fuzzyPreprocess(self):
        pass

    def interceptProcess(self):
        
        if self.category=='time':
            self.timeInterceptProcess()
        elif self.category=='content':
            self.contentInterceptPreprocess()
        else:
            self.fuzzyInterceptPreprocess()

    def timeInterceptProcess(self):
        # DEBUG
        print "sleep for %d delay"%(self.parameter)
        time.sleep(self.parameter)
        self.nCond=self.nCond-1
           
    def contentInterceptPreprocess(self):
        pass
    
    def fuzzyInterceptPreprocess(self):
        pass
    
           
    def runComponent(self):
        ''' Function which search for the list of json files in the specified 
        configuration folder and calls the jsonParse function in loops. This 
        is also part of Issue #5. '''
        while self.nCond>0:
            try:
                self.currentTest.run()
            except Automaton.InterceptionPoint,Pkt:
                print "from the runcomponent I am in %s",(self.currentTest.state.state)
                self.interceptProcess()
                self.currentTest.accept_packet(self.currentTest.intercepted_packet)
                # Here we can add post process in case of fuzzy
        print "Tested specified tested number of conditions"
        time.sleep(15)
        print "stopping the automaton"
        self.currentTest.stop()
        print " Now ... Exiting..."


class ConfigExpert(object):
    
    def __init__(self):
        self.json = {}
        self.json['category']=''
        self.json['parameter']=''
        self.Nconfig=0

    def process(self, rawJson):
        ''' Here the raw Json data from the file is process to 
        match the processed json structure.'''
        
        self.json = copy.deepcopy(rawJson)
        self.Nconfig=self.Nconfig+1
        self.json['Nconfigs']=self.Nconfig
        # Since we know that for the time category the parameter 
        # is a delay. It is converted to an Integer Value.
        
        if 'time' in self.json['category']:
            self.json['parameter']=int(rawJson['parameter'])
            # Here currently trying to test the same config 
            # from the json file for 5 times
            # But this must be computed from the number of condtions 
            # given for that specific test-ID 
            self.json['Nconditions']=2
    
    def getRegistry(self):
        return self.json
    