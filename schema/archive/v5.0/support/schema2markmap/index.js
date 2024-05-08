// Author: Chandan BN (c) 2021
//   (1) convert CVE JSON schema to a mindmap

var ml = require('markmap-lib')
var Transformer = ml.Transformer;
var fillTemplate = ml.fillTemplate;
var sw = require('@cloudflare/json-schema-walker');
var rp = require('json-schema-ref-parser');
var fold = ['metrics', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0', 'supportingMedia',
  'tags', 'impacts', 'configurations', 'workarounds', 'solutions', 'exploits',
  'timeline', 'credits', 'tags', 'taxonomyMappings', 'adp'];
var symbol = { object: '', array: '[]', string: '', boolean: '☯', number: '', integer: '', undefined: '' };
const fs = require('fs');
var markmap = require('markmap-view');
const { Markmap, loadCSS, loadJS } = markmap;

let forDeletion = ['properties', 'items', 'anyOf', 'allOf', 'oneOf'];

var markdown = "# CVE JSON Record\n";

function postfunc(obj, path, parent, parentPath) {
  if (path[1] && isNaN(path[1])) {
    var depth = parentPath.filter(i => !forDeletion.includes(i)).length;
    var reqStart = "";
    var reqEnd = "";

    if (parent?.required?.includes(path[1])) {
      reqStart = "<b>";
      reqEnd = "</b>";
    }
    markdown += ("  ".repeat(depth)
      + "* " + reqStart + path[1] + reqEnd
      + ' ' + (fold.includes(path[1]) ? '<!-- fold -->' : '')
      + symbol[obj.type]
      + (obj.examples ? 'e.g., `' + obj.examples[0] + '`' : '')
      + (obj.enum ? '`' + obj.enum.join('` `') + '`' : ''))
      + '\n';
  }
}

async function schemaMindMap() {
  var cveSchema = await rp.dereference(process.argv[2]);
  markdown += "## Published <style>b {font-weight:800}</style>\n";
  sw.schemaWalk(cveSchema.oneOf[0], postfunc, null);

  markdown += "## Rejected <style>b {font-weight:800}</style>\n";
  sw.schemaWalk(cveSchema.oneOf[1], postfunc, null);

  const transformer = new Transformer();

  // transform markdown
  const { root, features } = transformer.transform(markdown);

  // get assets required by used features
  var assets = transformer.getUsedAssets(features);

  // create mindmap html
  var html = fillTemplate(root, assets);
  html = html.replace('<title>Markmap</title>', '<title>CVE JSON v5 Mindmap</title>');
  console.log(html);
}

schemaMindMap();
