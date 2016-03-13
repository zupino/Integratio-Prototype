from tczDebug import TCZee
from _pyio import __metaclass__
import json
import glob # file fetching
import re # string splitting
import ast # str to dict

'''Approach for Test Server using the Meta classes.'''


class Tester(object):
    
    def __init__(self):
        self.testServers=[]

    # Reads all the json files from 'config' folder and returns a list with N dictionaries
    def jsonParse(self):
        allJsonContent = []
        for filename in glob.glob('./configs_1/*.json'):
            openFile = open(filename)
            readFile = openFile.read()
            readFile = ''.join(re.split(r'[\n\t]\s*', readFile))# Spaces are converted to next line '/n' and tabs as '/t'
            singleFileDict = ast.literal_eval(readFile)
            allJsonContent.append(singleFileDict) # contains the content of all the available JSON files contents
            openFile.close()# closing the current JSON file
        return allJsonContent


    def createTestServer(self, jsonDict=None):
        ''' Function calls the Tester Component defined in Tester.py'''
        tester = TestServer(jsonDict)
    
    def run(self):
        ''' Function which search for the list of json files in the specified 
        configuration folder and calls the jsonParse function in loops. This 
        is also part of Issue #5. '''
        pass


class TesterServerMeta(type):
    def __init__(cls, name, bases, clsdict):
        jsonDict=clsdict[args]
        if jsonDict['category'] == 'time':
            def new_method(self):
                clsdict[jsonDict['testType']](self)
            setattr(cls, jsonDict['testType'], new_method)

class TestServer(TCZee):
    __metaclass__ = TesterServerMeta