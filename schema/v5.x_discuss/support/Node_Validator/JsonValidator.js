require('colors')
const cveSchema = require('./jsonSchema')
const Validator = require('jsonschema').Validator
const v = new Validator()
const cve = require('./' + process.argv[2])

const schema = cveSchema.cveSchema5
v.addSchema(schema, '/https://www.first.org/cvss/cvss-v3.1.json?20190610')
v.addSchema(schema, '/https://www.first.org/cvss/cvss-v3.0.json?20170531')
v.addSchema(schema, '/https://www.first.org/cvss/cvss-v2.0.json?20170531')
const result = v.validate(cve, schema, { nestedErrors: true })

if (result.valid) {
  console.log('SUCCESSFUL CVE JSON schema validation'.green)
} else {
  result.errors.forEach(element => {
    console.log(element.stack.yellow)
  })
  console.log('CVE JSON schema validation FAILED'.red)
}
