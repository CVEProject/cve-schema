#!/usr/bin/env python

###################################################################################
###################### Python Script to validate JSON file ########################
###################################################################################

### Usage ###

# To run this script you must have the following:
#	Python 2.7
#	Python modules json and jsonschema installed on your machine.

# Simply run following command in terminal to validate json file against schema:

# ./cmdlinejsonvalidator.py example.json jsonschema.json

# Where example will be the name of your JSON file and jsonschema is the schema 
# you wish to compare the json file against.

# ***NOTE***
# If you do not place the script in same directory as the jsonschema file and 
# json file you will need to use absolute/relative path names to the files as
# your arguments.

###################################################################################
###################################################################################
import sys
import json
import jsonschema
from jsonschema import validate
from jsonschema.validators import extend
from jsonschema.exceptions import ValidationError
from jsonschema import Draft4Validator



def jsonvalidation(argv1,argv2):
	# Point to the location of the most currently used schema
	schema_location= str(argv2)
	# Open the file for reading
	schema_file = open(schema_location,"r")

	# Read the file into string
	schema_string = schema_file.read()

	# Close the file after reading into string
	schema_file.close()

	# In order to use the validation function you need to have JSON objects
	# Now load JSON string into a JSON object
	schema_load = json.loads(schema_string)

	# Lets point to the location of the input JSON file.
	json_location = str(argv1)

	# Open the file for reading
	json_file = open(json_location,"r")

	# Read the contents of file
	json_string= json_file.read()

	# Close the file after reading into string
	json_file.close()

	# In order to use the validation function you need to have JSON objects
	# Now load JSON string into a JSON object
	json_load = json.loads(json_string)

	try:
		validate(json_load,schema_load)
		sys.stdout.write("Record passed validation \n")
	except jsonschema.exceptions.ValidationError as incorrect:
		v = Draft4Validator(schema_load)
		errors = sorted(v.iter_errors(json_load), key=lambda e: e.path)
		for error in errors:
			sys.stderr.write("Record did not pass: \n")
			sys.stderr.write(str(error.message)+ "\n")

##################################################################################
##################################################################################

jsonvalidation(sys.argv[1],sys.argv[2])
