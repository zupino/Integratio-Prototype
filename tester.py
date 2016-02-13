from tczDebug import TCZee
from _pyio import __metaclass__

'''Approach for Test Server using the Meta classes.'''

class TesterMeta(type):
    def __init__(cls, name, bases, clsdict):
        jsonDict=clsdict[args]
        if jsonDict['category'] == 'time':
            def new_method(self):
                clsdict[jsonDict['testType']](self)
            setattr(cls, jsonDict['testType'], new_method)

class Tester(TCZee):
    __metaclass__ = TesterMeta