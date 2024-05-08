from jsonschema import *
import json
import sys

jsource = None
jschema = None

if len(sys.argv) == 3:
  argv = sys.argv  
  jsource = json.load(open(argv[1])) #'cve502example.json'
  jschema = json.load(open(argv[2])) #'cve502.schema'

  D7validator = Draft7Validator(jschema)
  hasErrors = 0
  for error in sorted(D7validator.iter_errors(jsource), key=str):
    hasErrors += 1
    print('Schema object with error: ', error.validator)
    print('ERROR CONTEXT', error.context)
    #print(error.message)
    print('')
    print('---------------------------------------------')
    print('')
  
  if hasErrors > 0:
    print('Found ', hasErrors, ' error(s)')
  else:
    print('Source was valid against schema')
else:
  print('Usage: python D7Validator.py [json source file] [json schema file]')
  
   
