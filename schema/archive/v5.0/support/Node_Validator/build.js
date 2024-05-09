const fs = require("fs")
const path = require("path")
const Ajv = require('ajv').default;
const standaloneCode = require("ajv/dist/standalone").default
const addFormats = require('ajv-formats').default;
const schema = require("../../docs/CVE_JSON_5.0_bundled.json")

function reduceSchema(o) {
    for(prop in o) {
        if(typeof(o[prop])=='object') {
            reduceSchema(o[prop])
        } else if (prop == "description" && typeof(o[prop])=='string') {
            delete o[prop]
        } else if (prop == "title" && typeof(o[prop])=='string') {
            delete o[prop]
        }
    }
    return o;
}
var rSchema = reduceSchema(schema);

const ajv = new Ajv({code: {source: true, optimize: 10}})
addFormats(ajv);
const validate = ajv.compile(rSchema)
let moduleCode = standaloneCode(ajv, validate)

// Now you can write the module code to file
fs.writeFileSync(path.join(__dirname+'/dist', "cve5validator.js"), moduleCode)
