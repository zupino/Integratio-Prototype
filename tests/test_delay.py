# content of test_delay.py

import sys
sys.path.append('../lib')
import tcz 
import requests
import pytest
import io
import json
import time

@pytest.fixture
def runConnector():
    # Starting the Connector thread
    fileConfig = io.open('../configs/delay.json')
    config = json.load(fileConfig)
    con = tcz.Connector(config, debug=3)
    con.runbg()
    return con

#    def setup_method(self, test_content_500):
#        fileConfig = io.open('../configs/content.json')
#        config = json.load(fileConfig)
#        con = tcz.Connector(config, debug=3)
#        con.run()

def test_delay(runConnector):
#    with pytest.raises(requests.exceptions.Timeout):
        r = requests.get('http://192.168.13.1/500', timeout=5)
        assert 0
        
