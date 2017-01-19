# DRAFT - CVE ID JSON File Format 4.0

This describes the CVE ID JSON format version 4.0, this file format primarily covers CVE ID but also CVE Mentors and CNAs

CVE_* is a reserved keyword. Essentially every CVE ID file is a JSON Object that contains more top level objects which in turn contain objects/arrays/booleans/etc. We have some required top level objects: CVE_data_type (what is this file?), CVE_data_format (who’s format is it in?) and CVE_data_version (what version of the data format is this?) for all types.

CVE_* keywords are officially documented (this document), if you see one that isn’t here then it’s not an official keyword, and you can ignore it. To add/modify/suggest changes to CVE_* keywords and their data structures please do X (issue in GitHub? TBD) so that we can consider it. 

# CVE ID JSON root level object

The CVE ID JSON format is comprised of a number of strings (CVE_data_type, CVE_data_format, CVE_data_version) and then a variety of top level objects, referred to as "containers" that can in turn contain more container objects, strings, lists of data and so on. Essentially the "root" object is just a JSON object "{}".

# CVE JSON string items

There are several special string values that can exist at the root level of the CVE ID JSON data, and one special one, the CVE_data_version, which can exist in the root or within any container.

## CVE_data_type

This string identifies what kind of data is held in this JSON file. This is mandatory and designed to prevent problems with attempting to detect what kind of file this is. Valid values for this string are CVE, CNA, CVEMENTOR. 

Must contain: the CVE data type

Mandatory in: root level

Optional in: none

## CVE_data_format

This string identifies what data format is used in this JSON file. This is mandatory and designed to prevent problems with attempting to detect what format of data is used. Valid values for this string are MITRE, it can also be user defined (e.g. for internal use). 

Must contain: the CVE data format

Mandatory in: root level

Optional in: all containers

## CVE_data_version

This identifies which version of the data format is in use. This is mandatory and designed to prevent problems with attempting to detect what format of data is used.

Must contain: the data version

Mandatory in: root level, any containers not in same version as parent container/root level object

Optional in: all containers

# CVE ID JSON containers 

These objects can in turn contain more objects, arrays, strings and so on. The reason for this is so that each top level object type can contain self identifying data such as CVE_Data_version. Most objects can in turn contains virtually any other object. In general if you traverse into the nested tree of objects you should not encounter any chains that contains more than one instance of a given object container. Simply put you should not for example encounter a chain such as: root, CVE_affects, CVE_configuration, CVE_workaround, CVE_configuration. Please note that this rule may be subject to change as we get new container types and use cases. 

## CVE_data_meta 

This is meta data about the CVE ID such as the CVE ID, who requested it, who assigned it, when it was requested, when it was assigned, the current state (PUBLIC, REJECT, etc.) and so on. 

Must contain: CVE ID (CNA requirement: [CVEID])

Mandatory in: root level

Optional in: none

## CVE_affects

This is the root level container for affected vendors and in turn their affected technologies, products, hardware, etc. It only goes in the root level. 

Must contain: At least one CVE_vendor definition

Mandatory in: root level

Optional in: none

## CVE_vendor

This is the container for affected vendors, it only goes in the CVE_affects container. 

Must contain: At least one CVE_product definition

Mandatory in: CVE_affects

Optional in: none

## CVE_product

This is the container for affected technologies, products, hardware, etc.

Must contain: At least one affected item by name (CNA requirement: [PRODUCT])

Mandatory in: CVE_vendor

Optional in: none

## CVE_version 

This is the container for listing the affected/non affected/fixed versions of a given technology, product, hardware, etc.

Must contain: At least one affected version (CNA requirement: [VERSION])

Mandatory in: CVE_product

Optional in: none

## CVE_description 

This is a description of the issue. It can exist in the root level or within virtually any other container, the intent being that for example different products, and configuraitons may result in different impacts and thus descriptions of the issue. 

Must contain: At least one description (CNA requirement: [DESCRIPTION])

Mandatory in: root level

Optional in: all containers

## CVE_configuration 

This is configuration information (format to be decided, we may for example support XCCDF or simple text based descriptions). It is generally meant to contain additional containers (e.g. CVE_description, CVE_impact). 

Must contain: At least one configuration

Mandatory in: none

Optional in: all containers

## CVE_references 

This is reference data in the form of URLs or file objects (uuencoded and embedded within the JSON file, exact format to be decided, e.g. we may require a compressed format so the objects require unpacking before they are "dangerous"). 

Must contain: At least one reference item  (CNA requirement: [REFERENCES])

Mandatory in: root level

Optional in: all containers

## CVE_workaround  

This is workaround information, format to be decided. 

Must contain: At least one workaround

Mandatory in: none

Optional in: all containers

## CVE_exploit 

This is exploit information, format to be decided. 

Must contain: At least one exploit / information about exploitation

Mandatory in: none

Optional in: all containers

## CVE_timeline 

This is timeline information (different than CVE_credit in that it may be historical events for which nobody can be directly credited), format to be decided. 

Must contain: At least one timeline entry

Mandatory in: none

Optional in: all containers

## CVE_credit 

This is credit information (different than CVE_timeline in that these are specific things being credited to specific people/organizations/etc.), format to be decided. 

Must contain: At least one credit entry

Mandatory in: none

Optional in: all containers

## CVE_problemtype 

This is problem type information (e.g. CWE identifier).

Must contain: At least one entry, can be text, OWASP, CWE, others may be added (CNA requirement: [PROBLEMTYPE])

Mandatory in: none

Optional in: all containers

## CVE_impact 

This is impnact type information (e.g. a text description, CVSSv2, CVSSv3, etc.). 

Must contain: At least one entry, can be text, CVSSv2, CVSSv3, others may be added

Mandatory in: none, please note there is a good chance this container may become required as part of the standard, currently the DWF requires it.

Optional in: all containers

# Examples

## Minimal structure needed for CVE

```
{
  "CVE_data_type": "CVE",
  "CVE_data_format": "MITRE",
  "CVE_data_version": "4.0",
  "CVE_data_meta": {
    "CVE_data_version": "4.0 - optional, to show nesting of various elements",
    "CVE_ID": "CVE-2017-900000",
    "CVE_date_requested": "2017-01-01",
    "CVE_date_assigned": "2017-01-02",
    "CVE_requestor": "kurt@seifried.org",
    "CVE_assigner": "kurt@seifried.org"
  },
  "CVE_affects": {
    "CVE_vendor": {
      "CVE_data_version": "4.0 - optional, to show nesting of various elements",
      "CVE_vendor_data": [
        {
          "CVE_vendor_name": "Example corp.",
          "CVE_product": {
            "CVE_data_version": "4.0 - optional, to show nesting of various elements",
            "CVE_products_data": [
              {
                "CVE_data_version": "4.0 - optional, to show nesting of various elements",
                "CVE_product_name": "Example product",
                "CVE_product_version": "1.0",
                "CVE_product_affected": "="
              }
            ]
          }
        },
        {
          "CVE_vendor_name": "Evil corp.",
          "CVE_product": {
            "CVE_data_version": "4.0 - optional, to show nesting of various elements",
            "CVE_products_data": [
              {
                "CVE_product_name": "Evil product",
                "CVE_product_version": "2.0",
                "CVE_product_affected": "="
              }
            ]
          }
        }
      ]
    }
  },
  "CVE_description": {
    "CVE_data_version": "4.0 - optional, to show nesting of various elements",
    "CVE_description_data": [
      {
        "lang": "eng",
        "value": "String description of issue"
      }
    ]
  },
  "CVE_references": {
    "CVE_data_version": "4.0 - optional, to show nesting of various elements",
    "CVE_reference_data": [
      {
        "url": "string for url location",
        "name": "string Name of reference i.e. if advisory has name",
        "publish_date": "DATE-TIMESTAMP of reference release to public"
      }
    ]
  },
  "CVE_problemtype": {
    "CVE_data_version": "4.0 - optional, to show nesting of various elements",
    "CVE_problemtype_data": [
      {
        "description": [
          {
            "lang": "string ISO 639-2",
            "value": "string description of problem_type, must be this OR CWE OR OWASP"
          }
        ],
        "cwe": [
          "strings of cwes",
          "strings separated by commas"
        ],
        "owasp": [
          "string of OWASP information",
          "strings separated by commas"
        ]
      }
    ]
  }
}
```

## More complicated example with product with configuration and specific description

The following example has a product with its own description, and a configuration for that product with it's own description in turn. 

```
{
  "CVE_data_type": "CVE",
  "CVE_data_format": "MITRE",
  "CVE_data_version": "4.0",
  "CVE_data_meta": {
    "CVE_ID": "CVE-2017-900000",
    "date_requested": "2017-01-01",
    "date_assigned": "2017-01-02",
    "requestor": "kurt@seifried.org",
    "assigner": "kurt@seifried.org"
  },
  "CVE_affects": {
    "CVE_vendor": {
      "CVE_product": {
        "products_affected": [
          {
            "product_name": "Example product",
            "product_version": "1.0",
            "product_affected": "=",
            "CVE_description": {
              "lang": "eng",
              "value": "String description of issue"
            },
            "CVE_impact": {
              "CVE_impact_metrics": {
                "cvss2": {},
                "cvss3": {}
              }
            },
            "CVE_configuration": {
              "XCCDF": "string value",
              "CVE_description": {
                "lang": "eng",
                "value": "String description of issue"
              }
            }
          },
          {
            "product_name": "Example product",
            "product_version": "1.1",
            "product_affected": "=<"
          }
        ]
      }
    }
  },
  "CVE_description": {
    "lang": "eng",
    "value": "String description of issue"
  },
  "CVE_references": {
    "references": [
      {
        "url": "string for url location",
        "name": "string Name of reference i.e. if advisory has name",
        "publish_date": "DATE-TIMESTAMP of reference release to public"
      }
    ]
  },
  "CVE_problemtype": {
    "problems": [
      {
        "description": [
          {
            "lang": "string ISO 639-2",
            "value": "string description of problem_type"
          }
        ],
        "cwe": [
          "strings of cwes",
          "strings separated by commas"
        ],
        "owasp": [
          "string of OWASP information",
          "strings separated by commas"
        ]
      }
    ]
  }
}
```

