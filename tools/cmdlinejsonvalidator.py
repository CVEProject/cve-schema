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
from jsonschema import Draft4Validator


def jsonvalidation(json_doc_path, json_schema_path):
    with open(json_schema_path, 'r') as fp:
        schema_doc = json.load(fp)

    # Open the file for reading
    with open(json_doc_path, 'r') as fp:
        try:
            json_doc = json.load(fp)
        except ValueError as err:
            sys.stderr.write("Failed to parse JSON : \n")
            sys.stderr.write("  " + str(err) + "\n")
            raise SystemExit

    try:
        validate(json_doc, schema_doc)
        sys.stdout.write("Record passed validation \n")
    except jsonschema.exceptions.ValidationError as incorrect:
        v = Draft4Validator(schema_doc)
        errors = sorted(v.iter_errors(json_doc), key=lambda e: e.path)
        for error in errors:
            sys.stderr.write("Record did not pass: \n")
            sys.stderr.write(str(error.message) + "\n")


def main():
    import argparse

    parser = argparse.ArgumentParser(description='validate a JSON file')
    parser.add_argument('jsondoc', type=str, help='path/to/doc.json')
    parser.add_argument('schema', type=str, help='path/to/schema.json')
    args = parser.parse_args()

    jsonvalidation(args.jsondoc, args.schema)


if __name__ == '__main__':
    main()
