#! /usr/bin/python

from scapy.all import *
from tester import *
from functools import wraps
import json
import glob # file fetching
import sys

# To be used when working on local interface l0
#conf.L3socket = L3RawSocket
sys.path.append('.')

if __name__=='__main__':
    
    log_scapy.setLevel(1)
    log_interactive.setLevel(1)
    log_runtime.setLevel(1)
    log_loading.setLevel(1)

    plainJson={}
    # creating Test Server Factory 
       
    #create Configuration Expert
    configExpert = ConfigExpert()
    
    # Poll the json files from the config folder
    for fileName in glob.glob('./configs/*.json'):
        with open(fileName) as dataFile:
            plainJson = json.load(dataFile)
        # call the configuration expert to normalize the- json dict
        configExpert.process(plainJson)
    # Only for debug purpose
    print "Json Registry:%s"%(configExpert.getRegistry())
    
    # Creating the teser object for the jsonRegistry dict
    comp = Tester(jsonDict=configExpert.getRegistry())
    
    # This runComponent loops over all the normalized json config 
    # respective to individual test case configs..
    comp.runComponent()
    