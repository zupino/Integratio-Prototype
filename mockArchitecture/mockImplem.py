'''
Created on 24.02.2016

@author: desikabj
'''

import time
import types
import inspect
from functools import wraps

def dummyDecorator(func):
    """Dummy decorator dunction to mock the Automaton State decorators.

    This is used by the mock TCZeeDummy class to emulate the actual 
    scenario for our TCP state machine.

    Args:
        func: the function or method object to decorated.

    Returns:
        returns the decorated function object.

    Raises:
        None.
    """
    def wrapped(*args, **kw):
        print "Dummy Tczee Decorator"
        func(*args, **kw)
    return wrapped


class TCZeeDummy(object):
    """Mock TCZee class.


    Attributes:
        tcpHeader -  parameter used for content category test cases.
    """

    def __init__(self):
        self.tcpHeader = "Mocck header"

    # mocking the method with the mock decorator.
    # few mock tcp states.
    @dummyDecorator
    def dummyRecevie_syn(self):
        print 'I am Mock function for Receive syn in TCZee'
    
    def dummyRecevie_ack(self):
        print 'I am Mock function for Receive Ack in TCZee'
        print self.tcpHeader
    
    # The decorators are defined as the static methods to define in the 
    # same scope to avoid overlapping scope while updating the tcpHeader  
    # attribute for content type tests.
    @staticmethod
    def contentDecorator(func):
        @wraps(func)
        def wrapped(self, *args, **kwargs):
            print "Inside content Wrapper. calling method %s now..."%(func.__name__)
            self.tcpHeader = 'I updated the header.. Now :)'
            response = func(self, *args, **kwargs)
            return response
        return wrapped
    
    @staticmethod
    def timeDecorator(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            print "Inside time Wrapper. calling method %s now..."%(func.__name__)
            response = func(*args, **kwargs)
            time.sleep(10)
            return response
        return wrapped
        
       
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
    class DecoratedMetaclass(type):

        def __new__(self, class_name, bases, namespace):
            if decorator is not None and category is 'time':
                for key, value in list(bases[0].__dict__.items()):
                    if callable(value) and key in fName:
                        setattr(bases[0], key, decorator(value))
                return type.__new__(self, class_name, bases, namespace)
            else:
                return type.__new__(self, class_name, bases, namespace)
        def __init__(self, class_name, bases, namespace):
            if category is not 'content':
                return type.__init__(self, class_name, bases, namespace)
            else:
                for key, value in list(bases[0].__dict__.items()):
                    if callable(value) and key in fName:
                        setattr(bases[0], key, decorator(value))
                return type.__init__(self, class_name, bases, namespace)
  
    return DecoratedMetaclass

def dynamicServerTemplate(decorator=None, fName='dummyRecevie_syn', category=None):

    class TestServer(TCZeeDummy):
        __metaclass__ = decorating_meta(decorator, fName, category)
        pass
    return TestServer
        
        
# This method is used for the discussion to clarify Why we need metaclass in FIRST PLACE!
def for_all_methods(namec,decorator):

    def decorate(cls):
        for name, fn in inspect.getmembers(cls, inspect.ismethod):
            print name, type(name)
            setattr(cls, name, decorator(fn))
        return cls
    return decorate

