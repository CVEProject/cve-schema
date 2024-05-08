const fs = require('fs');
const readline = require('readline');
const docs= {
'/containers/cna/affected/product:maxLength': "Product name is too long! If you are listing multiple products, please use separate product objects.",
'/containers/cna/affected/product:minLength': "A product name is required.",
'/containers/cna/affected/versions/version:maxLength': "Version name is too long! If you are listing multiple versions, please encode as an array of version objects.",
'/containers/cna/metrics/cvssV3_0:required': "CVSS objects are incomplete. Please provide a valid vectorString at the minimum in your CVE-JSON v4 submission."

}
/*
function cvePath(value) {
  var realId = value.match(/(CVE-(\d{4})-(\d{1,12})(\d{3}))/);
  if (realId) {
    var id = realId[1];
    var year = realId[2];
    var bucket = realId[3];
    return (year + '/' + bucket + 'xxx/' + id + '.json')
  }
}
*/
const validateCve = require('./dist/cve5validator.js')
var errorStat = {};
var warnStat = {};
var errorCount = {};
var yStat = {};
var invalid = 0;
var warns = 0;
var total = 0;
var ignore = { '': 1, '/cveMetadata/state': 1, '/containers/cna/references/url': 0}
function validate(line) {
  if (line) {
    var parts = line.match(/(CVE-(\d+)-\d+)/);
    var year = "unknown";
    var id = "unknown";
    if (parts) {
      year = parts[2];
      id = parts[1];
    }
    try {
      if (!fs.lstatSync(line).isDirectory()) {
        var cveFile = fs.readFileSync(line);
        var cve = JSON.parse(cveFile);
        var warnings = cve.containers?.cna.x_ConverterErrors;
        //delete cve.x_ValidationErrors;
        var assigner = "default";
        try {
          assigner = cve.containers?.cna?.x_legacyV4Record?.CVE_data_meta?.ASSIGNER;
          if(!assigner) {
            assigner = cve.containers?.cna?.providerMetadata?.shortName;
          }
        } catch (e) {
          console.error(e.message);
        }
        total++;

        if(warnings) {
          warns++;
          errorCount[assigner]++;
          for (const key in warnings) {
            var w = 'Warning: ' + warnings[key].error;
            //console.log(key);
            if(!errorStat[assigner]) {
              errorStat[assigner] = {}
              errorCount[assigner] = 0
            }
            if(!errorStat[assigner][key]) {
              errorStat[assigner][key] = [];
            }
            if(!errorStat[assigner][key][w]) {
              errorStat[assigner][key][w] = [];
            }
            errorStat[assigner][key][w].push(id);
          }
        }
        var valid = validateCve(cve);
        if (!valid) {
          var errseen = false;
          validateCve.errors.forEach(err => {
            var path = err.instancePath.replace(/\/\d+\/?/g, "/")
            if (!ignore[path]) {
              var e = 'Error: ' + err.keyword;
              if (!errorStat[assigner]) {
                errorStat[assigner] = {}
                errorCount[assigner] = 0
              }
              if (!errorStat[assigner][path]) {
                errorStat[assigner][path] = {}
              }
              if (!errorStat[assigner][path][e]) {
                errorStat[assigner][path][e] = []
              }
              errorStat[assigner][path][e].push(id);
              errseen = true;
            }
          });
          if (errseen) {
            errorCount[assigner]++;
            invalid++;
            yStat[year] ? yStat[year]++ : (yStat[year] = 1);
          }
        }
      }
    } catch (e) {
      console.error(e.message);
    }
  }
}
/* Example error
  {
    instancePath: '/cveMetadata/state',
    schemaPath: '#/properties/state/enum',
    keyword: 'enum',
    params: { allowedValues: [Array] },
    message: 'must be equal to one of the allowed values'
  },
  */
var rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

function report() {
  console.log(`
  <html><head><style>
  body{
    font-family:Roboto Mono,sans-serif;
  }
  summary {
    cursor: pointer;
  }
  .grid {
    display: inline-grid;
    gap: 5px;
    grid-template: repeat(1, 1fr) / repeat(8, 1fr);
  }
  </style></head>
  <body><h2>
  ${total} upconverted CVEs: ${warns} warnings and ${invalid} errors.
  </h2>
  `)
  for (const y in yStat) {
    console.log(`<li>year ${y} - ${yStat[y]}</li>`)
  }

  Object.keys(errorStat).sort().forEach(x => {
    var domain = x.substring(x.indexOf('@') + 1)
    console.log(`<h3 id=${domain}><img style="vertical-align:middle" width=32 height=32 src="https://www.google.com/s2/favicons?sz=32&domain_url=${domain}/"> ${domain} <a href="#${domain}">[link]</a></h3>`)
    for (const k in errorStat[x]) {
      var alist = errorStat[x][k];
      for (const a in alist) {
        var ids = [...new Set(alist[a])];
        console.log(`<blockquote><details id="${x}-${k}-${a}"><summary>[${ids.length} CVEs] ${a} - <i>field ${k}</i>  <a href="#${x}-${k}-${a}">[link]</a>:</summary>`)
        if(docs[x + ':' + k]) {
          console.log(`<p>`+docs[x + ':' + k]+'</p>')
        }
        console.log('<blockquote class="grid">')
        for (const c of ids.sort()) {
          console.log(` <a href="https://vulnogram.github.io/seaview?${c}">${c}</a>`)
        }
        console.log('</blockquote></details></blockquote>')
      }
    }
  });
}

rl.on('line', validate)
rl.on('close', report)