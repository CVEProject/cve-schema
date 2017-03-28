//
// Runs an HTTP server to prompt for CVE assignment information and
// outputs that in a format for submission to MITRE.
//

var listen_on = 38103;
var output_format = 'json40';

var title = 'CVE CNA Assignment Information Form';
var instructions = 'Use this form to enter CNA assignment information for an single id to be submitted to MITRE. Note that the form does not have support for multiple vendors, products, versions, or references.';

var header = '<html>' + '\n' +
             '<head>' + '\n' +
             '<title>' + title + '</title>' + '\n' +
             '</head>' + '\n';
var footer = '</html>' + '\n';

var http = require('http');
var qs = require('querystring');


var server = http.createServer(function(request, response) {
  var headers = request.headers;
  var method = request.method;
  var url = request.url;
  var body = [];
  request.on('error', function(err) {
    console.error(err);
  }).on('data', function(chunk) {
    body.push(chunk);
  }).on('end', function() {
    body = Buffer.concat(body).toString();

    if (method.toLowerCase() == 'get') {
      body = '<body>' + '\n' +
             '<p>' + instructions + '</p>' + '\n' +
             '\n' +
             '<form method="POST" action="/">' + '\n' + 
             '<table>' + '\n' + 
             '<tr><th>CVE id : </th><td><input type="text" size="15" name="id"></td></tr>' + '\n' +
             '<tr><th>Vendor : </th><td><input type="text" size="25" name="vendor"></td></tr>' + '\n' +
             '<tr><th>Product(s) : </th><td><input type="text" size="80" name="product"></td></tr>' + '\n' +
             '<tr><th>Version(s) : </th><td><input type="text" size="80" name="version"></td></tr>' + '\n' +
             '<tr><th>Problem type : </th><td><input type="text" size="80" name="problem_type"></td></tr>' + '\n' +
             '<tr><th>References : </th><td><input type="text" size="80" name="references"></td></tr>' + '\n' +
             '<tr><th>Description : </th><td><textarea rows="5" cols="80" name="description"></textarea></td></tr>' + '\n' +
             '<tr><th>&nbsp;</th><td><input type="submit">' + '\n' +
             '</table>' + '\n' + 
             '</form>' + '\n' +
             '</body>';
    }
    else if (method.toLowerCase() == 'post') {
      var post = qs.parse(body);

      var errs = [];

      // Validate submitted data.
      if (!post['id']) {
        errs.push("The CVE id is required!");
      }
      else if (!post['id'].match(/^CVE-\d{4}-\d{4,}$/)) {
        errs.push("'" + post['id'] + "' is not a valid CVE id!");
      }
      if (!post['vendor']) {
        errs.push("The vendor name is required!");
      }
      if (!post['product']) {
        errs.push("Product name information is required!");
      }
      if (!post['version']) {
        errs.push("Product version information is required!");
      }
      if (!post['problem_type']) {
        errs.push("Problem type information is required!");
      }
      if (!post['references']) {
        errs.push("At least one reference is required!");
      }
      else {
        if (!post['references'].match(/^(ftp|http)s?:\/\/[^\/]+(\/\S+)?$/)) {
          errs.push("'" + post['references'] + "' is not a valid reference!");
        }
      }
      if (!post['description']) {
        errs.push("A description is required!");
      }

      if (errs.length == 0) {
        body = '<p>Now submit the following information to MITRE via either the <a target="_blank" href="https://cveform.mitre.org/">CVE request form</a> or an e-mail to <a href="mailto:cve@mitre.org">cve@mitre.org</a>.<br></p>' + '\n' +
               '\n' +
               '<pre>' + '\n';
        if (output_format == 'json40') {
          body += JSON.stringify({
            "data_type": "CVE",
            "data_format": "MITRE",
            "data_version": "4.0",
            "CVE_data_meta": {
              "ID": post['id']
            },
            "affects": {
              "vendor": {
                "vendor_data": [
                  {
                    "vendor_name": post['vendor'],
                    "product": {
                      "product_data": [
                        {
                          "product_name": post['product'],
                          "version": {
                            "version_data": [
                              {
                                "version_value": post['version'],
                              },
                            ],
                          },
                        },
                      ],
                    }
                  }
                ],
              },
            },
            "problemtype": {
              "problemtype_data": [
                {
                  "description": [
                    {
                      "lang": "eng",
                      "value": post['problem_type'],
                    }
                  ],
                },
              ],
            },
            "references": {
              "reference_data": [
                {
                  "url": post['references'],
                },
              ],
            },
            "description": {
              "description_data": [
                {
                  "lang": "eng",
                  "value": post['description'],
                },
              ],
            }

          }, null, 2);
        }
        else if (output_format == 'flat') {
          body += 
               '[CVEID]:' + post['id'] + '\n' +
               '[PRODUCT]:' + post['vendor'] + ' ' + post['product'] + ' ' + post['version'] + '\n' +
               '[VERSION]:' + post['version'] + '\n' +
               '[PROBLEMTYPE]:' + post['problem_type'] + '\n' +
               '[REFERENCES]:' + post['references'] + '\n' +
               '[DESCRIPTION]:' + post['description'] + '\n';
        }
        body += '</pre>' + '\n'

        if (output_format == 'json40') {
          body += '<p><b>Note:</b> The JSON 4.0 specification is still in draft.' + '\n';
        }
      }
      else {
        body = '<p><b>The following error(s) must be addressed:</b></p>' + '\n' + 
               '<ul>' + '\n';
        errs.forEach(function(item, index) {
          body += '  <li>' + item + '</li>' + '\n';
        });
        body += '</ul>' + '\n';
      }
    }
    data = header + '\n' + body + '\n' + footer;
    response.writeHead(200, {
        'Content-Type': 'text/html',
        'Content-Length': data.length
    });
    response.write(data);
  })
});


server.listen(listen_on, 'localhost');
console.log("server listening on localhost:" + listen_on + ".");
