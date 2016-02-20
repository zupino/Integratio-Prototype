from tczDebug import TCZee
from _pyio import __metaclass__

'''Approach for Test Server using the Meta classes.'''


class Tester(object):
    
    def __init__(self):
        self.testServers=[]

    def jsonParse(self, file='test.json'):
        ''' Function to be completed by raja for Issue #5 to parse a specific 
        json file and return as python dictionary.'''
        pass

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