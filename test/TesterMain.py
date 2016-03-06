import json
import unittest
import glob # file fetching
import re # string splitting
import ast # str to dict

####################################################################################################################
#                   READS ALL THE JSON FILES IN THE ROOT FOLDER
####################################################################################################################
# Load all the Json File
allFileContent = {}
for filename in glob.glob('*.json'):
    openFile = open(filename)
    readFile = openFile.read()
    readFile = ''.join(re.split(r'[\n\t]\s*', readFile))# Spaces are converted to next line '/n' and tabs as '/t'
    singleFileDict = ast.literal_eval(readFile)
    allFileContent.update(dict(singleFileDict)) # contains the content of all the available JSON files contents

####################################################################################################################
#                   TEST CASE TO TEST THE ABOVE RESULT
####################################################################################################################
# Testing the above read single JSON file.
    def test_one_argument(self):
        jsonFile2Test03 = allFileContent["Test03_2"]
        self.assertTrue(jsonFile2Test03["state"] == "I am testing this content")


