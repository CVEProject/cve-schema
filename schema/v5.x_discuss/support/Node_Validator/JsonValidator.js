const colors = require('colors/safe')
const cveSchema = require('./jsonSchema')
const Validator = require('jsonschema').Validator
const v = new Validator()
const cve = require('./' + process.argv[2])
const cveState = cve.CVE_data_meta.STATE
let schema

// For validating schema 5.0
if (cveState === 'PUBLIC') {
  schema = cveSchema.publicSchema
  v.addSchema(schema, '/https://www.first.org/cvss/cvss-v3.1.json?20190610')
  v.addSchema(schema, '/https://www.first.org/cvss/cvss-v3.0.json?20170531')
  v.addSchema(schema, '/https://www.first.org/cvss/cvss-v2.0.json?20170531')
} else if (cveState === 'RESERVED') {
  schema = cveSchema.reservedSchema
} else if (cveState === 'REJECT') {
  schema = cveSchema.rejectSchema
} else {
  console.log({ message: 'CVE JSON schema validation FAILED', errors: ['instance.CVE_data_meta.STATE is not one of enum values'] })
}

const result = v.validate(cve, schema, { nestedErrors: true })

if (result.valid) {
  console.log('message: ' + colors.green('SUCCESSFUL CVE JSON schema validation'))
} else {
  const temp = result.errors
  const errors = []

  temp.forEach((error) => {
    if (error.stack !== '') {
      const e = error.stack.split(':', 2).toString()
      errors.push(e)
    }
  })

  console.log('message: ' + colors.red('CVE JSON schema validation FAILED.'))
  console.log('errors : ' + colors.yellow(errors))
}
