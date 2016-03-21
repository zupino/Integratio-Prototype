'''
Created on 13.03.2016

@author: Rajadurai Kanniappan
'''

import unittest
from tester import jsonParse
# Unittest for testing the JSON parse
class testJsonParse(unittest.TestCase):

# testing 'jsonParse' from three JSON files
    def test_jsonParse(self):
        jsonList = jsonParse("args")

        # The entire dctionary is NOT tested, because python generates dict in an unsorted order. SO, only a particular content of a dict is tested
         # Testing contents from JSON file 1
        content0 = jsonList[0]
        self.assertEqual(content0["category"], 'content-based')

        # Testing contents from JSON file 2
        content1 = jsonList[1]
        self.assertEqual(content1["state"], 'Delay testing')

        # Testing contents from JSON file 3
        content2 = jsonList[2]
        self.assertEqual(content2["listeningPort"], 80)

unittest.main()



