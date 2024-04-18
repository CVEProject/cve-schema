const fs = require('fs');
const path = require('path');
const validateCve = require('../Node_Validator/dist/cve5validator.js')
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;

const ignore = {
  '': 1,
  '/cveMetadata/state': 1,
  '/cveMetadata': 1,
  '/dataVersion': 1,
  '/containers/cna/references/url': 0
}
var cnas = {};
var cnaIndex = {};
var errorStat = {};
var warnStat = {};
var errorCount = {};
var yStat = {};
var invalid = 0;
var warns = 0;
var total = 0;

const start = `
<html><head><title>CVE Quality Report</title><style>
body { font-family:Roboto Mono,sans-serif; margin:3em; }
summary { cursor: pointer; }
a { text-decoration: none; color: #356cac; }
.grid { display:grid; gap: 5px; grid-template-columns: repeat(auto-fill, minmax(8em,1fr)); }
</style></head>
<body>`

async function loadCNAs(data) {
  for(c of data) {
    try {
      var em = c.contact[0].email[0].emailAddr;
      var host= em.substr(em.indexOf('@')+1);
      u = new URL('https://www.'+host);
      c.i = u.href;
      c.n = c.organizationName;
    } catch(e) {
    }
    cnas[c.shortName]=c;
  }

}
async function getCNAs() {
  //var data = require('./CNAsList.json');
  //loadCNAs(data); return;
  const cnaList = 'https://raw.githubusercontent.com/CVEProject/cve-website/dev/src/assets/data/CNAsList.json'
  const res = await fetch(cnaList);
  if (res.ok) {
    const data = await res.json();
    loadCNAs(data);
  }
}

function cveLink(id) {
  return 'https://github.com/CVEProject/cvelistV5/tree/main/cves/' + cveRepoPath(id);
}

function cveRepoPath(value) {
var realId = value.match(/(CVE-(\d{4})-(\d{1,12})(\d{3}))/);
if (realId) {
  var id = realId[1];
  var year = realId[2];
  var bucket = realId[3];
  return (year + '/' + bucket + 'xxx/' + id + '.json')
}
}

async function getReport(dir) {
  const files = fs.readdirSync(dir, { withFileTypes: true });
  for (const file of files) {
    if (file.isDirectory()) {
      getReport(path.join(dir, file.name));
    } else {
      if (file.name.match((/CVE-(\d{4})-(\d{1,12})(\d{3})/))) {
        var cveFile = fs.readFileSync(path.join(dir, file.name));
        var cve = JSON.parse(cveFile);
        var v = valididate(cve);
        var q = qualityCheck(cve);
        total++;
        if(!v) {
          invalid++; 
        }
        if(!q) {
          warns++; 
        }
      }
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

function addError(cve, err) {
  var id = cve.cveMetadata.cveId;

  var shortName = cve.cveMetadata?.assignerShortName || 'default';
  if(!cnaIndex[shortName]) {
    cnaIndex[shortName] = [];
  }

  //remove oneOf numbers
  var path = err?.instancePath?.replace(/\/\d+\/?/g, "/");
  if (!ignore[path]) {
    var prop = err.params?.additionalProperty || '';
    var e = `Problem: <b>${err.keyword} ${prop}!</b> - ${err.message}`;
    if (!errorStat[shortName]) {
      errorStat[shortName] = {}
      errorCount[shortName] = 0
    }
    if (!errorStat[shortName][path]) {
      errorStat[shortName][path] = {}
    }
    if (!errorStat[shortName][path][e]) {
      errorStat[shortName][path][e] = []
    }
    errorStat[shortName][path][e].push(id);
    errseen = true;
  }
}

function valididate(cve) {
  var valid = validateCve(cve);
  errseen = false;
  if (!valid) {
    validateCve.errors.forEach(err=>{addError(cve, err)});
  }
  return !errseen;
}

function qualityCheck(cve) {
  var warned = false;
  var c = checkCVSS(cve);
  if(c){
    addError(cve, c);
    warned = true;
  }
/*  c = checkLinkRot(cve);
  if(c) {
    addError(cve, c);
    warned = true;
  }*/
  if(warned) {
    return false;
  } else { 
    return true;
  }
}

const four04List = [
  'www.securityfocus.com',
  'osvdb.org',
  'online.securityfocus.com',
  'patches.sgi.com',
  'docs.info.apple.com',
  'h20000.www2.hp.com',
  'labs.idefense.com',
  'wiki.rpath.com',
  'source.codeaurora.org',
  'code.wireshark.org',
  'h20564.www2.hp.com',
  'www.linux-mandrake.com',
  'erpscan.io',
  'downloads.securityfocus.com',
  'www.atstake.com',
  'hermes.opensuse.org',
  'itrc.hp.com',
  'ftp.caldera.com',
  'packetstorm.linuxsecurity.com',
  'www1.itrc.hp.com'
]

const four04 = {};
for (const key of four04List) {
  four04[key] = 1;
}

function checkLinkRot(cve) {
  if(cve.containers?.cna?.references) {
    for(r of cve.containers?.cna?.references) {
      try{
        var u = new URL(r.url);
        if (four04[u.host] && !(r.tags && r.tags.includes('broken-link'))) {
          return {
            instancePath: '/containers/cna/references',
            schemaPath: '#/properties/url',
            keyword: 'Broken link to ' + u.host,
            params: {  },
            message: 'Reference points to defunct site. Replace or add a broken-link tag.'
          }
        }
      } catch(e) {
        console.log('Error parsing URL' + r.url)
      }
    }
  }
  return false;
}

function checkCVSS(cve) {
  if(cve.containers.cna?.metrics) {
    for(m of cve.containers.cna?.metrics) {
      var cvss = m.cvssV3_1 || m.cvssV3_0;
      if(cvss) {
        if ((cvss.baseSeverity == 'CRITICAL' && cvss.baseScore >= 9 && cvss.baseScore <= 10)
          || (cvss.baseSeverity == 'HIGH' && cvss.baseScore >= 7 && cvss.baseScore < 9)
          || (cvss.baseSeverity == 'MEDIUM' && cvss.baseScore >= 4 && cvss.baseScore < 7)
          || (cvss.baseSeverity == 'LOW' && cvss.baseScore >= 0.1 && cvss.baseScore < 4)
          || (cvss.baseSeverity == 'NONE' && cvss.baseScore == 0)) {
            //console.log('valid CVSS ');
          } else {
            return {
              instancePath: '/containers/cna/metrics',
              schemaPath: '#/properties', // TODO?
              keyword: 'Bad CVSS',
              params: {  },
              message: 'Mismatched CVSS score and level'
            }
          }
      }
    }
  }
  return false;
}

async function checkAffected(cve) {

}


run(process.argv[2]);

async function run(dir) {
  await getCNAs();
  await getReport(dir);
  await printReport();
}


const docs = {
'/containers/cna/affected/product:maxLength': "Product name is too long! If you are listing multiple products, please use separate product objects.",
'/containers/cna/affected/product:minLength': "A product name is required.",
'/containers/cna/affected/versions/version:maxLength': "Version name is too long! If you are listing multiple versions, please encode as an array of version objects.",
'/containers/cna/metrics/cvssV3_0:required': "CVSS objects are incomplete. Please provide a valid vectorString at the minimum in your CVE-JSON v4 submission."
}


function printReport() {
  console.log(start + 
  `<h2>CVE Quality Workgroup Report</h2><h3> ${total} CVE analyzed: Found ${invalid} schema errors, ${warns} quality issues</h2>`)
  /*for (const y in yStat) {
    console.log(`<li>year ${y} - ${yStat[y]}</li>`)
  }*/

  Object.keys(errorStat).sort().forEach(shortName => {
    var i = cnas[shortName]?.i;
    var name = cnas[shortName]?.n ? cnas[shortName]?.n : shortName;
    console.log(`<h3 id=${shortName}><img style="vertical-align:middle" width=32 height=32 src="https://www.google.com/s2/favicons?sz=64&domain_url=${encodeURIComponent(i)}/"> ${name} <a href="#${shortName}">[link]</a></h3>`)
    for (const k in errorStat[shortName]) {
      var alist = errorStat[shortName][k];
      for (const a in alist) {
        var ids = [...new Set(alist[a])];
        console.log(`<blockquote><details id="${shortName}-${k}-${a}"><summary>[${ids.length} CVEs] ${a} - <i>field ${k}</i>  <a href="#${shortName}-${k}-${a}">[link]</a>:</summary>`)
        if(docs[shortName + ':' + k]) {
          console.log(`<p>`+docs[shortName + ':' + k]+'</p>')
        }
        console.log('<blockquote class="grid">')
        for (const c of ids.sort()) {
          console.log(` <a href="${cveLink(c)}">${c}</a>`)
        }
        console.log('</blockquote></details></blockquote>')
      }
    }
  });

  console.log('</body></html>');
}
/*  var index = start + '<h2>CVE Quality Workgroup Report: CVE Records Indexed by CNAs</h2><div class="grid">';
  for(x of Object.keys(cnaIndex).sort(new Intl.Collator('en',{numeric:true}).compare)) {
    var i = cnas[x]?.i;
    var name = cnas[x]?.n ? cnas[x]?.n : x;
    index = index + `<img style="vertical-align:middle" width=32 height=32 src="https://www.google.com/s2/favicons?sz=32&domain_url=${encodeURIComponent(i)}/"><br>${name}<br>${cnaIndex[x].length} records<br><br>`;
    //var report = start + `<h2>CVE Quality Workgroup Report: CVEs records belonging to ${name}</h2><blockquote class="grid">`;
    for (c in cnaIndex[x].sort(new Intl.Collator('en',{numeric:true}).compare)) {
      index += ` <a href="${cveLink(cnaIndex[x][c])}">${cnaIndex[x][c]}</a>`
    }
    //report = report + '</body</html>';
    //fs.writeFileSync('./reports/'+x+'.html',report);
  }
  fs.writeFileSync('./reports/index.html',index + '</div></body></html>');
}

rl.on('line', validate)
rl.on('close', report)

*/