'''
Created on 24.02.2016

@author: desikabj
'''
from mockArchitecture import *


if __name__ == '__main__':
    print 'Testing the actual TestServer class'
    TestServer=dynamicServerTemplate(decorator=None, fName='dummyRecevie_syn', category=None)
    serverObj = TestServer()    
    serverObj.dummyRecevie_syn()
    serverObj.dummyRecevie_ack()
    print '-----------------------------------'


    TestServer1 = dynamicServerTemplate(decorator=TCZeeDummy.timeDecorator, fName='dummyRecevie_syn', category='time')
    serverObj = TestServer1()    
    serverObj.dummyRecevie_syn()
    
    print '-----------------------------------'
    
    TestServer1 = dynamicServerTemplate(decorator=TCZeeDummy.contentDecorator, fName='dummyRecevie_ack', category='content')
    serverObj = TestServer1()    
    serverObj.dummyRecevie_ack()
    print '----------Exiting -----------------'