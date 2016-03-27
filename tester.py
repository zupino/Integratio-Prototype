from tcz.tczDebug import TCZee
from _pyio import __metaclass__
from scapy.automaton import Automaton_metaclass
import copy
from functools import wraps

'''Approach for Test Server using the Meta classes.'''

class TestServerFactory(object):
    
    def __init__(self):
        self.serverClassRegistry=[]
        self.serverObjectRegistry=[]

    def createTestServer(self, jsonDict=None):
        ''' Function calls the Tester Component defined in Tester.py'''
        
        if 'time' in jsonDict['category']:
            TestServer = TestServerFactory.dynamicServerTemplate(decorator=TCZee.timeDecorator,
                                                             fName=jsonDict['fName'],
                                                             category=jsonDict['category'])
            
            serverObject = TestServer(int(jsonDict['listeningPort']), delay=int(jsonDict['parameter']), debug=3)
            import pdb
            pdb.set_trace() 
            self.serverClassRegistry.append(TestServer)
            self.serverObjectRegistry.append(serverObject)

    def Run(self):
        ''' Function which search for the list of json files in the specified 
        configuration folder and calls the jsonParse function in loops. This 
        is also part of Issue #5. '''
        for server in self.serverObjectRegistry:
            server.run()

    @staticmethod
    def decorating_meta(decorator, fName, category):
        """Decorated function to generate dynamic meta classes. 
    
        This function is used to take in to account the config 
        parameters parsed from the json files and generate the 
        metaclass template for varying test scenarios. 
    
        Args:
            decorator: (Object) function object of decorated to be used in runtime
            fName: (String) the name of the function to be updated for a specific category
            category: (String) the test Category to decide the point of updation
    
        Returns:
            returns the metaclass template to be used by the  function dynamicServerTemplate()
    
        Raises:
            None.
        """
        class DecoratedMetaclassBase(Automaton_metaclass):
    
            def __new__(self, class_name, bases, namespace):
                if decorator is not None and category.encode('utf-8') == 'time':
                    import pdb
                    pdb.set_trace() 
                    for key, value in list(bases[0].__dict__.items()):
                        print '0'
                        if callable(value) and key is fName:
                            print '1', key, value, decorator, decorator(value)
                            setattr(bases[0], key, decorator(value))
                    return super(DecoratedMetaclassBase, self).__new__(self, class_name, bases, namespace)
                else:
                    return super(DecoratedMetaclassBase, self).__new__(self, class_name, bases, namespace)
      
        class DecoratedMetaclass(DecoratedMetaclassBase):
            def __new__(self, class_name, bases, namespace):
                print "M3 called for " + class_name
                return super(DecoratedMetaclass, self).__new__(self, class_name, bases, namespace)
        
        return DecoratedMetaclass
    
    @staticmethod
    def dynamicServerTemplate(decorator=None, fName='receive_finAck', category=None):
    
        class TestServer(TCZee):
            __metaclass__ =   TestServerFactory.decorating_meta(decorator, fName, category)
            pass
        return TestServer


class ConfigExpert(object):
    
    def __init__(self):
        self.json = {}
        self.json['category']=''
        self.json['fName']=''
        self.json['parameter']=''

    def process(self, rawJson):
        ''' Here the raw Json data from the file is process to 
        match the processed json structure.'''
        
        self.json = copy.deepcopy(rawJson)
        
        self.json['fName']='receive_finAck'
        
        # Since we know that for the time category the parameter 
        # is a delay. It is converted to an Integer Value.
        
        if 'time' in self.json['category']:
            self.json['parameter']=int(rawJson['parameter'])
        return self.json