#!/bin/bash
cd ../../
sed 's/file\://g' CVE_JSON_5.0.schema > tmp.json | generate-schema-doc --minify tmp.json docs/index.html
perl -pi -e 's/<svg.*?<\/svg>/&gt;/g' docs/index.html
node support/schema2markmap/index.js tmp.json > 'docs/mindmap.html'
node support/schema2markmap/schema-bundle.js tmp.json > 'docs/CVE_JSON_5.0_bundled.json'
rm tmp.json
cat support/docs/css_override.css >> docs/schema_doc.css
