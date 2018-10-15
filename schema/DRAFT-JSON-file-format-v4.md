# DRAFT - CVE ID JSON File Format 4.0

This describes the CVE ID JSON format version 4.0, and this file format primarily covers CVE ID but also CVE Mentors and CNAs.

CVE_* is a reserved keyword. Essentially every CVE ID file is a JSON Object that contains more top level objects which in turn contain objects/arrays/booleans/etc. We have some required top level objects: CVE_data_type (what is this file?), CVE_data_format (who’s format is it in?) and CVE_data_version (what version of the data format is this?) for all types.

CVE_* keywords are officially documented (this document), if you see one that isn’t here then it’s not an official keyword, and you can ignore it. To add/modify/suggest changes to CVE_* keywords and their data structures please do X (issue in GitHub? TBD) so that we can consider it. 

# Notes on data within the JSON file format

## Timestamps

Timestamps are in ISO 8601, as per the standard if no time zone is specified it is assumed to be local, obviously, that is sub optimal for CVE so we will probably need to require all timestamps have a time zone specified, ideally UTC. Alternatively we can make it a requirement for CNA's to only accept data that is well formed (e.g. timestamps must require timezone data) but then we run the risk of rejecting data that is useful because part of it is not "correct." 

## Leap seconds

Subtracted leap seconds should be acceptable as timestamps will only be off by a second or two at most (and only once in a very rare while), added leap seconds (e.g. 11:59:60) will be rounded down (e.g. 11:59:60 becomes 11:59:59) as we can live with this level of clock skewing. Please note that the CVE test data will likely include timestamps with leap seconds to ensure systems handle them properly if they are encountered, but as CVE data is then passed to other systems and processed in ways we can't know it is safer to get rid of leap seconds.  

## Unicode

Data may be Unicode encoded, titles, descriptions, researcher names, version numbers (people use alphabetical versioning, so we should expect this but in other character sets/languages). Data should no longer be assumed to be simple ASCII all the time. 

## UUencoded data

File objects associated with CVE IDs may sometimes be embedded within the JSON data as a UUncoded object (optionally zip compressed and password protected in the case where the data may trigger an AV scanner for example). Again, this data may be dangerous or actively hostile depending on what software you use to process it.

## Base64 data

File objects associated with CVE IDs may sometimes be embedded within the JSON data as a Base64 object (optionally zip compressed and password protected in the case where the data may trigger an AV scanner for example). Again, this data may be dangerous or actively hostile depending on what software you use to process it.

## Multiple line strings

For data (such as gpg keys, copies of text, etc.) that consists of a multiline string we will simply use "\n" to insert line breaks (JSON strings cannot have actual line breaks). An example of code that can generate such a JSON object is:

```
#!/usr/bin/python
import json
with open(“multi-line.txt", "r") as file:
    multilinestring=file.read()
jsonexample={“string_name”: multilinestring}
print json.dumps(jsonexample)
```

This is not ideally human readable, but there is no good simple solution for this unfortunately.

# CVE ID JSON root level object

The CVE ID JSON format is comprised of a number of strings (CVE_data_type, CVE_data_format, CVE_data_version) and then a variety of top level objects, referred to as "containers" that can in turn contain more container objects, strings, lists of data and so on. Essentially the "root" object is just a JSON object "{}".

# CVE JSON string items

There are several special string values that can exist at the root level of the CVE ID JSON data, and one special one, the CVE_data_version, which can exist in the root or within any container.

## data_type

This string identifies what kind of data is held in this JSON file. This is mandatory and designed to prevent problems with attempting to detect what kind of file this is. Valid values for this string are CVE, CNA, CVEMENTOR. 

Must contain: the CVE data type

Mandatory in: root level

Optional in: none

JSON data type: string

## data_format

This string identifies what data format is used in this JSON file. This is mandatory and designed to prevent problems with attempting to detect what format of data is used. Valid values for this string are MITRE, it can also be user defined (e.g. for internal use). 

Must contain: the CVE data format

Mandatory in: root level

Optional in: all containers

JSON data type: string

## data_version

This identifies which version of the data format is in use. This is mandatory and designed to prevent problems with attempting to detect what format of data is used.

Must contain: the data version

Mandatory in: root level, any containers not in same version as parent container/root level object

Optional in: all containers

JSON data type: string

# CVE ID JSON containers 

These objects can in turn contain more objects, arrays, strings and so on. The reason for this is so that each top level object type can contain self-identifying data such as CVE_Data_version. Most objects can in turn contains virtually any other object. In general, if you traverse into the nested tree of objects you should not encounter any chains that contains more than one instance of a given object container. Simply put you should not for example encounter a chain such as: root, CVE_affects, CVE_configuration, CVE_workaround, CVE_configuration. Please note that this rule may be subject to change as we get new container types and use cases. 

JSON data type: object

## CVE_data_meta 

This is meta data about the CVE ID such as the CVE ID, who requested it, who assigned it, when it was requested, when it was assigned, the current state (PUBLIC, REJECT, etc.) and so on. 

Must contain: CVE ID (CNA requirement: [CVEID]) and ASSIGNER

Mandatory in: root level

Optional in: none

JSON data type: object

### UPDATED 

DATE-TIMESTAMP - last update time for this entry

JSON data type: string

### SERIAL

INT - starts at 1, add 1 every time an entry is updated or changed

JSON data type: string

### ID

CVE-YEAR-NNNNNNN - the CVE ID in the format listed in http://cve.mitre.org/cve/identifiers/syntaxchange.html#new

JSON data type: string

### DATE_REQUESTED

DATE-TIMESTAMP - the date/time this issue was requested

JSON data type: string

### DATE_ASSIGNED

DATE-TIMESTAMP - the date/time this was assigned

JSON data type: string

### DATE_PUBLIC

DATE_PUBLIC - the date/time this issue went public if known

JSON data type: string

### REQUESTER

Requester ID - the requester of the CVE (email address)

JSON data type: string

### ASSIGNER

Assigner ID - the assigner of the CVE (email address)

JSON data type: string

### REPLACED_BY

replaced by data - a single CVE ID or list of CVE IDs (comma separated) 

JSON data type: string

### STATE

State of CVE - PUBLIC, RESERVED, REPLACED_BY, SPLIT_FROM, MERGED_TO

JSON data type: string

### TITLE

Short title - if the description is long we may want a short title to refer to

JSON data type: string

## affects

This is the root level container for affected vendors and in turn their affected technologies, products, hardware, etc. It only goes in the root level. 

Must contain: At least one vendor definition

Mandatory in: root level

Optional in: none

JSON data type: object

## vendor

This is the container for affected vendors, it only goes in the affects container. 

Must contain: At least one product definition (in vendor_data)

Mandatory in: affects, there must be at least one defined vulnerable product either in the form of a text description (via data defined in vendor, product, version) OR a affects_CPE OR a affects_SWID

Optional in: none

JSON data type: object

### vendor_data

This is an array of version values (vulnerable and not); we use an array so that different entities can make statements about the same vendor and they are separate (if we used a JSON object we'd essentially be keying on the vendor name and they would have to overlap). Also this allows things like data_version or description to be applied directly to the vendor entry.

Must contain: One of the vendor definitions must contains at least one product definition (so there must be a minimum of one full declaration of a vulnerable product)

Mandatory in: vendor

Optional in: none

JSON data type: array that contains objects

#### vendor_name

The vendor name

#### product

See the product for a full definition

## product

This is the container for affected technologies, products, hardware, etc.

Must contain: At least one affected item by name (CNA requirement: [PRODUCT])

Mandatory in: vendor

Optional in: none

JSON data type: object

### product_data

This is an array of version values (vulnerable and not); we use an array so that we can make multiple statements about the same product and they are separate (if we used a JSON object we'd essentially be keying on the product name and they would have to overlap). Also this allows things like data_version or description to be applied directly to the product entry.

Must contain: One of the product definitions must contains at least one version definition (so there must be a minimum of one full declaration of a vulnerable product)

Mandatory in: product

Optional in: none

JSON data type: array that contains objects

#### product_name

The product name

#### version

See the CVE_version for a full definition

## version 

This is the container for listing the affected/non-affected/fixed versions of a given technology, product, hardware, etc.

Must contain: At least one affected version (CNA requirement: [VERSION]) 

Mandatory in: product

Optional in: none

JSON data type: object

### version_data

This is an array of version values (vulnerable and not); we use an array so that we can make multiple statements about the same version and they are separate (if we used a JSON object we'd essentially be keying on the version name/number and they would have to overlap). Also this allows things like data_version or description to be applied directly to the product entry. This also allows more complex statements such as "Product X between versions 10.2 and 10.8" to be put in a machine-readable format. As well since multiple statements can be used multiple branches of the same product can be defined here.

Must contain: One of the product definitions must contains at least one version definition (so there must be a minimum of one full declaration of a vulnerable product)

Mandatory in: version

Optional in: none

JSON data type: array that contains objects

#### version_value

The version name/value (e.g. 10.0, 3.1, "IceHouse")

#### version_affected

A string value such as "=" (just that version is affected), "!" (not affected), "?" (unknown),  <, >, <=, >=, !>, !<, !=>, !=<, ?>, ?<, ?<=, ?>=.

| version_affected | definition |
|----------|---------------|
| = | affects **version_value** |
| <  | affects versions prior to **version_value** |
| > | affects versions later than **version_value** |
| <= | affects **version_value** and prior versions |
| >= | affects **version_value** and later versions |
| ! | doesn't affect **version_value** |
| !< | doesn't affect versions prior to **version_value** |
| !> | doesn't affect versions later than **version_value** |
| !<= | doesn't affect **version_value** and prior versions |
| !>= | doesn't affect **version_value** and later versions |
| ? | status of **version_value** is unknown |
| ?< | status of versions prior to **version_value** is unknown |
| ?> | status of versions later than **version_value** is unknown |
| ?<= | status of **version_value** and prior versions is unknown |
| ?>= | status of **version_value** and later versions is unknown |

?, ?<, ?<= may be used to state that a vulnerability has not been evaluated on certain versions such as unsupported versions.

?>, ?>= can be used to indicate unfixed vulnerabilities, where it is not known if a future version will ever have a fix.

## affects_CPE

This is the container for affected products defined by CPE. 

Must contain: At least one CPE definition (in affects_CPE_data)

Mandatory in: affects, there must be at least one defined vulnerable product either in the form of a text description (via data defined in vendor, product, version) OR a affects_CPE OR a affects_SWID

Optional in: none

JSON data type: object

## affects_CPE_data

This is an array of CPE values (vulnerable and not), we use an array so that we can make multiple statements about the same version and they are separate (if we used a JSON object we'd essentially be keying on the CPE name and they would have to overlap). Also this allows things like CVE_data_version or CVE_description to be applied directly to the product entry. This also allows more complex statements such as "Product X between versions 10.2 and 10.8" to be put in a machine-readable format. As well since multiple statements can be used multiple branches of the same product can be defined here.

Must contain: One of the product definitions must contains at least one CVE_version definition (so there must be a minimum of one full declaration of a vulnerable product)

Mandatory in: affects_CPE

Optional in: none

JSON data type: array that contains objects

## affects_SWID

This is the container for affected products defined by CPE. 

Must contain: At least one CPE definition (in affects_CPE_data)

Mandatory in: CVE_affects, there must be at least one defined vulnerable product either in the form of a text description (via data defined in vendor, product, version) OR a affects_CPE OR a affects_SWID

Optional in: none

JSON data type: object

## affects_SWID_data

This is an array of SWID values (vulnerable and not), we use an array so that we can make multiple statements about the same version and they are separate (if we used a JSON object we'd essentially be keying on the SWID name and they would have to overlap). Also this allows things like CVE_data_version or CVE_description to be applied directly to the product entry. This also allows more complex statements such as "Product X between versions 10.2 and 10.8" to be put in a machine-readable format. As well since multiple statements can be used multiple branches of the same product can be defined here.

Must contain: One of the product definitions must contains at least one CVE_version definition (so there must be a minimum of one full declaration of a vulnerable product)

Mandatory in: affects_SWID

Optional in: none

JSON data type: array that contains objects

## description 

This is a description of the issue. It can exist in the root level or within virtually any other container, the intent being that for example different products, and configurations may result in different impacts and thus descriptions of the issue. 

Must contain: At least one description (CNA requirement: [DESCRIPTION])

Mandatory in: root level

Optional in: all containers

JSON data type: object

## configuration 

This is configuration information (format to be decided, we may for example support XCCDF or simple text based descriptions). It is generally meant to contain additional containers (e.g. CVE_description, CVE_impact). 

Must contain: At least one configuration

Mandatory in: none

Optional in: all containers

JSON data type: object

## references 

This is reference data in the form of URLs or file objects (uuencoded and embedded within the JSON file, exact format to be decided, e.g. we may require a compressed format so the objects require unpacking before they are "dangerous"). 

Must contain: At least one reference item  (CNA requirement: [REFERENCES])

Mandatory in: root level

Optional in: all containers

JSON data type: object

## workaround  

This is workaround information, format to be decided. 

Must contain: At least one workaround

Mandatory in: none

Optional in: all containers

JSON data type: object

## exploit 

This is exploit information, format to be decided. 

Must contain: At least one exploit / information about exploitation

Mandatory in: none

Optional in: all containers

JSON data type: object

## timeline 

This is timeline information (different than CVE_credit in that it may be historical events for which nobody can be directly credited), format to be decided. 

Must contain: At least one timeline entry

Mandatory in: none

Optional in: all containers

JSON data type: object

## credit 

This is credit information (different than CVE_timeline in that these are specific things being credited to specific people/organizations/etc.), format to be decided. 

Must contain: At least one credit entry

Mandatory in: none

Optional in: all containers

JSON data type: object

## problemtype 

This is problem type information (e.g. CWE identifier).

Must contain: At least one entry, can be text, OWASP, CWE, please note that while only one is required you can use more than one (or indeed all three) as long as they are correct). (CNA requirement: [PROBLEMTYPE])

Mandatory in: none

Optional in: all containers

JSON data type: object

## impact 

This is impact type information (e.g. a text description, CVSSv2, CVSSv3, etc.). 

Must contain: At least one entry, can be text, CVSSv2, CVSSv3, others may be added

Mandatory in: none, please note there is a good chance this container may become required as part of the standard, currently the DWF requires it.

Optional in: all containers

JSON data type: object

### cvssv2

The CVSSv2 (https://www.first.org/cvss/v2/guide) scoring data, split up into Base Metrics Group (BM), Temporal Metrics Group (TM) and Environmental Metrics Group (EM). 

Must contain: At least one data point

Mandatory in: none

Optional in: impact

JSON data type: object

#### BM

The Base Metrics Group

JSON data type: object

##### AV

The Access Vector, must be "L", "A" or "N".

JSON data type: string

##### AC

The Access Complexity, must be "H", "M" or "L".

JSON data type: string

##### AU

The Authentication, must be "M", "S" or "N".

JSON data type: string

##### C

The Confidentiality impact, must be "N", "P" or "C".

JSON data type: string

##### I

The Integrity impact, must be "N", "P" or "C".

JSON data type: string

##### A

The Availability impact, must be "N", "P" or "C".

JSON data type: string

##### SCORE

The CVSSv2 Base Metrics Group score assuming all elements are present.

JSON data type: string

#### TM

The Temporal Metrics Group.

JSON data type: object

##### E

Exploitability, must be "U", "POC", "F", "H" or "ND".

JSON data type: string

##### RL

Remediation Level, must be "OF", "TF", "W", "U" or "ND". 

JSON data type: string

##### RC

Report Confidence, must be "UC", "UR", "C" or "ND".

JSON data type: string

##### SCORE

The CVSSv2 Temporal Metrics Group score assuming all elements are present.

JSON data type: string

#### EM

The Environmental Metrics Group.

JSON data type: object

##### CDP

The Collateral Damage Potential, must be "N", "L", "LM", "MH", "H" or "ND".

JSON data type: string

##### TD

The Target Distribution, must be "N", "L", "M", "H" or "ND".

JSON data type: string

##### CR

Security Requirements Confidentiality, must be "L", "M", "H" or "ND".

JSON data type: string

##### IR

Security Requirements Integrity, must be "L", "M", "H" or "ND".

JSON data type: string

##### AR

Security Requirements Availability, must be "L", "M", "H" or "ND".

JSON data type: string

##### SCORE

The CVSSv2 Temporal Metrics Group score assuming all elements are present.

JSON data type: string

### cvssv3

The CVSSv3 (https://www.first.org/cvss/specification-document) scoring data.

Must contain: At least one data point

Mandatory in: none

Optional in: impact

JSON data type: object

#### BM

JSON data type: object

The Base Metric Group scoring information.

##### AV

The Attack Vector, must be "N", "A", "L" or "P".

JSON data type: string

##### AC

The Attack Complexity, must be "L" or "H".

JSON data type: string

##### PR

The Privileges Required, must be "N", "L" or "H".

JSON data type: string

##### UI

The User Interaction, must be"N", or "R".

JSON data type: string

##### S

The Scope, must be "U", or "C".

JSON data type: string

##### C

The Confidentiality Impact, must be "H", "L" or "N".

JSON data type: string

##### I

The Integrity Impact, must be "H", "L" or "N".

JSON data type: string

##### A

The Availability Impact, must be "H", "L" or "N".

JSON data type: string

##### SCORE

The CVSSv3 score.

JSON data type: string

#### TM

The Temporal Metric Group scoring information.

JSON data type: object

##### E

Exploit Code Maturity, must be "X", "H", "F", "P" and "U".

JSON data type: string

##### RL

Remediation Level, must be "X", "U", "W", "T" and "O".

JSON data type: string

##### RC

Report Confidence, must be "X", "C", "R" and "U".

JSON data type: string

#### EM

The Environmental Metric Group scoring information.

JSON data type: object

##### CR

Security Requirements Confidentiality, must be "X", "H", "M" or "L".

JSON data type: string

##### IR

Security Requirements Integrity, must be "X", "H", "M" or "L".

JSON data type: string

##### AR

Security Requirements Availability, must be "X", "H", "M" or "L".

JSON data type: string

##### MAV

The Modified Attack Vector, must be "N", "A", "L" or "P".

JSON data type: string

##### MAC

The Modified Attack Complexity, must be "L" or "H".

JSON data type: string

##### MPR

The Modified Privileges Required, must be "N", "L" or "H".

JSON data type: string

##### MUI

The Modified User Interaction, must be "N", or "R".

JSON data type: string

##### MS

The Modified Scope, must be "U", or "C".

JSON data type: string

##### MC

The Modified Confidentiality Impact, must be "H", "L" or "N".

JSON data type: string

##### MI

The Modified Integrity Impact, must be "H", "L" or "N".

JSON data type: string

##### MA

The Modified Availability Impact, must be "H", "L" or "N".

JSON data type: string

## source

This is the source information (who discovered it, who researched it, etc.) and optionally a chain of CNA information (e.g. the originating CNA and subsequent parent CNAs who have processed it before it arrives at the MITRE root). 

Must contain: IF this is in the root level it MUST contain a CNA_chain entry, IF this source entry is NOT in the root (e.g. it is part of a vendor statement) then it must contain at least one type of data entry.

Mandatory in: none

Optional in: all containers

JSON data type: object

# Examples

The following are a minimal example (as defined by MITRE in the CVE CNA Guidelines) and a more complete example.

## Minimal structure needed for CVE

```
{
	"data_type": "CVE",
	"data_format": "MITRE",
	"data_version": "4.0",
	"CVE_data_meta": {
		"ID": "CVE-YYYY-NNNNNN",
		"ASSIGNER": "Example email address"
	},
	"affects": {
		"vendor": {
			"vendor_data": [
				{
					"vendor_name": "Example corp.",
					"product": {
						"product_data": [
							{
								"product_name": "Example product",
								"version": {
									"version_data": [
										{
											"version_value": "1.0"
										}
									]
								}
							}
						]
					}
				}
			]
		}
	},
	"problemtype":{
		"problemtype_data":[
			{
				"description":[
					{
						"lang": "string ISO 639-2",
						"value":"string description of problem_type"
					}
				]
			}
		]
	},
	"references":{
		"reference_data":[
			{
				"url":"string for url location"
			}
		]
	},
	"description":{
		"description_data":[
			{
				"lang": "string ISO 639-2",
				"value":"string description of vulnerability"
			}
		]
	}
}
```
## Minimal example needed for CVE [single entry]
```
{
	"data_type": "CVE",
	"data_format": "MITRE",
	"data_version": "4.0",
	"CVE_data_meta": {
		"ID": "CVE-2005-4900",
		"ASSIGNER": "cve@mitre.org"
	},
	"affects": {
		"vendor": {
			"vendor_data": [
				{
					"vendor_name": " ",
					"product": {
						"product_data": [
							{
								"product_name": "sha-1",
								"version": {
									"version_data": [
										{
											"version_value": "sha-1"
										}
									]
								}
							}
						]
					}
				}
			]
		}
	},
	"problemtype":{
		"problemtype_data":[
			{
				"description":[
					{
						"lang": "eng",
						"value":"some sort of cryptography problem"
					}
				]
			}
		]
	},
	"references":{
		"reference_data":[
			{
				"url":"http://ia.cr/2007/474"
			},
			{
				"url":"http://shattered.io/"
			},
			{
				"url":"http://www.cwi.nl/news/2017/cwi-and-google-announce-first-collision-industry-security-standard-sha-1"
			},
			{
				"url":"https://arstechnica.com/security/2017/02/at-deaths-door-for-years-widely-used-sha1-function-is-now-dead/"
			},
			{
				"url":"https://security.googleblog.com/2015/12/an-update-on-sha-1-certificates-in.html"
			},
			{
				"url":"https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html"
			},
			{
				"url":"https://sites.google.com/site/itstheshappening"
			},
			{
				"url":"https://www.schneier.com/blog/archives/2005/02/sha1_broken.html"
			},
			{
				"url":"https://www.schneier.com/blog/archives/2005/08/new_cryptanalyt.html"
			}
		]
	},
	"description":{
		"description_data":[
			{
				"lang": "eng",
				"value":"SHA-1 is not collision resistant, which makes it easier for context-dependent attackers to conduct spoofing attacks, as demonstrated by attacks on the use of SHA-1 in TLS 1.2. NOTE: this CVE exists to provide a common identifier for referencing this SHA-1 issue; the existence of an identifier is not, by itself, a technology recommendation."
			}
		]
	}
}
```

## Minimal example needed for CVE [multiple entries]
```
[
	{
		"data_type": "CVE",
		"data_format": "MITRE",
		"data_version": "4.0",
		"CVE_data_meta": {
			"ID": "CVE-2005-4900",
			"ASSIGNER": "cve@mitre.org"
		},
		"affects": {
			"vendor": {
				"vendor_data": [
					{
						"vendor_name": " ",
						"product": {
							"product_data": [
								{
									"product_name": "sha-1",
									"version": {
										"version_data": [
											{
												"version_value": " "
											}
										]
									}
								}
							]
						}
					}
				]
			}
		},
		"problemtype":{
			"problemtype_data":[
				{
					"description":[
						{
							"lang": "eng",
							"value":"some sort of cryptography problem"
						}
					]
				}
			]
		},
		"references":{
			"reference_data":[
				{
					"url":"http://ia.cr/2007/474"
				},
				{
					"url":"http://shattered.io/"
				},
				{
					"url":"http://www.cwi.nl/news/2017/cwi-and-google-announce-first-collision-industry-security-standard-sha-1"
				},
				{
					"url":"https://arstechnica.com/security/2017/02/at-deaths-door-for-years-widely-used-sha1-function-is-now-dead/"
				},
				{
					"url":"https://security.googleblog.com/2015/12/an-update-on-sha-1-certificates-in.html"
				},
				{
					"url":"https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html"
				},
				{
					"url":"https://sites.google.com/site/itstheshappening"
				},
				{
					"url":"https://www.schneier.com/blog/archives/2005/02/sha1_broken.html"
				},
				{
					"url":"https://www.schneier.com/blog/archives/2005/08/new_cryptanalyt.html"
				}
			]
		},
		"description":{
			"description_data":[
				{
					"lang": "eng",
					"value":"SHA-1 is not collision resistant, which makes it easier for context-dependent attackers to conduct spoofing attacks, as demonstrated by attacks on the use of SHA-1 in TLS 1.2. NOTE: this CVE exists to provide a common identifier for referencing this SHA-1 issue; the existence of an identifier is not, by itself, a technology recommendation."
				}
			]
		}
	},
	{
		"data_type": "CVE",
		"data_format": "MITRE",
		"data_version": "4.0",
		"CVE_data_meta": {
			"ID": "CVE-2004-2761",
			"ASSIGNER": "cve@mitre.org"
		},
		"affects": {
			"vendor": {
				"vendor_data": [
					{
						"vendor_name": " ",
						"product": {
							"product_data": [
								{
									"product_name": "MD5",
									"version": {
										"version_data": [
											{
												"version_value": " "
											}
										]
									}
								}
							]
						}
					}
				]
			}
		},
		"problemtype":{
			"problemtype_data":[
				{
					"description":[
						{
							"lang": "eng",
							"value":"other"
						}
					]
				}
			]
		},
		"references":{
			"reference_data":[
				{
					"url":"http://blog.mozilla.com/security/2008/12/30/md5-weaknesses-could-lead-to-ce..."
				},
				{
					"url":"http://blogs.technet.com/swi/archive/2008/12/30/information-regarding-md5-c..."
				},
				{
					"url":"http://www.doxpara.com/research/md5/md5_someday.pdf"
				},
				{
					"url":"http://www.microsoft.com/technet/security/advisory/961509.mspx"
				},
				{
					"url":"http://www.phreedom.org/research/rogue-ca/"
				},
				{
					"url":"http://www.win.tue.nl/hashclash/SoftIntCodeSign/"
				},
				{
					"url":"http://www.win.tue.nl/hashclash/rogue-ca/"
				},
				{
					"url":"https://www.schneier.com/blog/archives/2005/02/sha1_broken.html"
				}
			]
		},
		"description":{
			"description_data":[
				{
					"lang": "eng",
					"value":"The MD5 Message-Digest Algorithm is not collision resistant, which makes it easier for context-dependent attackers to conduct spoofing attacks, as demonstrated by attacks on the use of MD5 in the signature algorithm of an X.509 certificate."
				}
			]
		}
	}

]
```
