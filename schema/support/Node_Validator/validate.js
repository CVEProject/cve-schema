const fs = require('fs');
const readline = require('readline');
const validateCve = require('./dist/cve5validator.js')
var invalid = 0;
var total = 0;
function validateFile(line) {
  if (line) {
    try {
      if (!fs.lstatSync(line).isDirectory()) {
        var cveFile = fs.readFileSync(line);
        var cve = JSON.parse(cveFile);
        total++;
        var valid = validateCve(cve);
        if (!valid) {
          invalid++;
          console.log(line + ' is invalid:');
          console.log(validateCve.errors);
        } else {
          console.log(line + ' is valid.');
        }
      }
    } catch (e) {
      console.error(e.message);
    }
  }
}

function report() {
  if (invalid == 0) {
    console.log(`Summary: All files PASSED validation.`)
  } else {
    console.log(`Summary: Validation FAILED for ${invalid} out of ${total} files!`)
  }
}
var usage = `
To validate one or more files
   $ node validate.js [file-1.json] [file-2.json] ... 

To validate a list of files in a file or on stdin:
   $ cat list.txt | node validate.js -e 
   $ find directory -name '*.json' | node validate.js -e 

To validate a single file via stdin:
  $ cat file.json | node validate.js

`
try {
  if (process.argv.length >= 3) {
    if (process.argv[2] && (process.argv[2].startsWith("-?") || process.argv[2].startsWith("-h"))) {
      console.log(usage)
    } else if (process.argv[2] && process.argv[2] == '-e') {
      var rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
        terminal: false
      });
      rl.on('line', validateFile)
      rl.on('close', report)
    } else {
      for (i = 2; i < process.argv.length; i++) {
        validateFile(process.argv[i]);
      }
      report();
    }
  } else {
    var cve = fs.readFileSync(0, 'utf-8');
    var valid = validateCve(JSON.parse(cve));
    if (!valid) {
      console.log('Input is invalid:');
      console.log(validateCve.errors);
    } else
      console.log('Input is valid.');
  }
} catch (e) {
  console.log(e.message);
  console.log(usage);
}