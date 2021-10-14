# CVE 5.0 Product and Version Encodings

CVE 5.0 introduces a simpler schema for defining a product
and a clearer schema for encoding the vulnerable versions of a product.
This document explains how to use these new schemas.

## Product Objects

In earlier versions of CVE, the `affected` object contained a `vendors` array,
and each `vendor` object contained a `products` array.
This forced specifying a vendor name even for products without vendors,
such as open source software.

To make it clearer how to identify open-source software, the CVE 5.0 `affected` object
contains the `products` array directly. Each product object can provide these properties:

 - `vendor`: the name of the organization, project, community, individual, or user
   that created or maintains the product or hosted service.
   When `collectionURL` and `packageName` are used,
   this field may specify the user or account associated with the package
   within the package collection.
   Formerly `vendorName` in the `vendor` object.

 - `product`: the name of the product itself.
   Formerly `productName`.

 - `collectionURL`: a URL identifying a software package collection.
   For example: `https://registry.npmjs.org` or `https://rubygems.org`.

 - `packageName`: the name of the package within the collection.
   For example: `left-pad`.

 - `cpes`: a list of affected products encoded in
   Common Platform Enumeration (CPE) 2.2 or 2.3 format.
   Formerly `affectsCpes` in the `affected` object.

 - `modules`: a list of the the affected components, features, modules, sub-components,
   sub-products, APIs, commands, utilities, programs, or functionalities`.

 - `programFiles`: a list of the affected source code files.

 - `programRoutines`: a list of the affected source code functions,
   methods, subroutines, or procedures.
   Each entry in the list is an object, and the `name` property is required.
   Other properties may be added as appropriate depending on the context.

 - `platforms`: a list of the affected platforms. When omitted, all platforms are assumed affected
   by this product description.
   Platforms may include execution environments, operating systems, virtualization technolgies,
   hardware models, or computing architectures.
   For example: `Android`, `iOS`, `macOS`, `Windows`, `x86`, `ARM`, `iPad`, `Chromebook`, `Docker`.
   Formerly in the `version` object.

 - `versions` and `defaultStatus`: a description of which versions are affected.
   (See next section for details.)

Most of these properties are optional.
The only requirements are identifying information and version information.
Identifying information may be provided by
_either_ `vendor` and `product` (for commercial offerings)
_or_ `collectionURL` and `packageName` (for open-source packages).
It is fine to list both pairs, such as in the case of a
commercial offering of packaged open-source products.
Version information is provided by `versions` and/or `defaultStatus`, detailed in the next section.

For example, a minimal entry for a commercial product:

	"affected": [
		{
			"vendor": "Widgets LLC",
			"product": "Flux Capacitor",
			"versions": [ ... ]
		}
	]

And for an open-source package:

	"affected": [
		{
			"collectionURL": "https://registry.npmjs.org",
			"packageName": "left-pad",
			"versions": [ ... ]
		}
	]

A product's affected versions may differ by platform.
In this case, multiple product objects would be listed in `affected` to
encode the different version information, with `platforms` restricting
each object to the relevant platform.
For example:

	"affected": [
		{
			"vendor": "Widgets LLC",
			"product": "Flux Capacitor",
			"platforms": ["macOS"],
			"versions": [ ... macOS versions ... ]
		},
		{
			"vendor": "Widgets LLC",
			"product": "Flux Capacitor",
			"platforms": ["Linux", "Windows"],
			"versions": [ ... Linux and Windows versions ... ]
		}
	]

## Version Status Decisions

The version encoding in CVE 5.0 comes with a clear algorithm for deciding
the status of a given product version—affected, unaffected, or unknown—while
still being easy for analysts and users to read and reason about.

In the product object, the `versions` and `defaultStatus` fields together
define an algorithmic mapping from any product version to its vulnerability status,
which is one of these strings:

 - `affected`: The version is affected by the vulnerability.
 - `unaffected`: The version is unaffected by the vulnerability.
 - `unknown`: It is unknown or unspecified whether the version is affected by the vulnerability.
   There can be many reasons for this status, including that an investigation
   has not been undertaken or that a vendor has not disclosed the status.

The `versions` field contains a list of version objects, each of which matches
a single version or a range of versions and specifies the status for the matched versions.
The versions matched by different objects should be disjoint;
that is, any specific version should be matched by at most one version object.

Versions not matched by any version object take the status listed in `defaultStatus`.
When `defaultStatus` is itself omitted, it defaults to `unknown`.

Omitting for the moment the details of how a particular entry
encodes the status for the versions it matches,
the algorithm for deciding the status of any particular version V is:

	for entry in product.versions {
		if entry matches V {
			return status specified by entry for V
		}
	}
	return product.defaultStatus

For example, this is an encoding in which versions 2.0.0 through 2.5.1 are affected,
2.5.2 and later 2.x.x are unaffected, and all other versions have unknown vulnerability status:

	"versions": [
		{ ... 2.0.0 through 2.5.1 affected ... },
		{ ... 2.5.2 through 2.x.x unaffected ... }
	]

For contrast, this is an encoding in which version 2.0.0 through 2.5.1 are affected,
and all other versions, both before 2.0.0 and after 2.5.1, are considered unaffected:

	"versions": [
		{ ... 2.0.0 through 2.5.1 affected ... }
	],
	"defaultStatus": "unaffected"

It is also possible to say that 2.5.2 and later are unaffected and everything else affected:

	"versions": [
		{ ... 2.5.2 and later unaffected ... }
	],
	"defaultStatus": "affected"

The specific choice of default depends mainly on how much the author of the CVE
understands about the affected version set. For example, a vulnerability researcher
who has tested a few specific versions and is making no claims about others might write:

	"versions": [
		{ ... 2.4 affected ... },
		{ ... 2.5 affected ... },
		{ ... 2.6 unaffected ... }
	]

In this case, `defaultStatus` defaults to `unknown`, which is correct for this report.

On the other hand, a vendor that knows there are exactly two affected versions
might write:

	"versions": [
		{ ... 2.4 affected ... },
		{ ... 2.5 affected ... }
	],
	"defaultStatus": "unaffected"

The CVE schema itself does not encourage or discourage any particular choice
of `defaultStatus`.
CVE encodings can use the `defaultStatus` that makes their status description clearest.

## Versions and Version Ranges

As mentioned above, each version object matches a single version
or a range of versions and specifies the status for the matched versions.

A version object specifies the status for a single version by setting only
the `version` and `status` fields. For example:

	{
		"version": "2.4",
		"status": "affected"
	}

Therefore, the full encoding of the final example in the previous section,
in which only 2.4 and 2.5 are affected, would be:

	"versions": [
		{"version": "2.4", "status": "affected"},
		{"version": "2.5", "status": "affected"}
	],
	"defaultStatus": "unaffected"

A version object can also specify the status for a range of versions,
by adding the `versionType` field as well as either the `lessThan` or `lessThanOrEqual` field.
For example, this version object specifies that semantic versions starting at 2.0.0 up to and including 2.5.1 are affected:

	{
		"version": "2.0.0",
		"versionType": "semver",
		"lessThanOrEqual": "2.5.1",
		"status": "affected"
	}

More precisely, this kind of version object matches any version V
such that `version` ≤ V ≤ `lessThanOrEqual`.
If the `lessThan` field is used instead of `lessThanOrEqual`, then
the condition is `version` ≤ V \< `lessThanOrEqual`.
For example, this version object specifies that semantic versions starting at 2.0.0 up to but not including 2.5.2 are affected:

	{
		"version": "2.0.0",
		"versionType": "semver",
		"lessThan": "2.5.2",
		"status": "affected"
	}

When identifying a precise range of affected versions,
the `lessThan` form is more common,
since it allows naming the exact version that introduced the fix.

The `versionType` is required when specifying ranges,
because there is no single definition of “less than” for versions.
Each different version numbering system has its own ordering rules.
For example, in [semantic versioning](https://semver.org/), `1.0.0-cr1` \< `1.0.0-m1`,
while [in Maven, the opposite is true](https://octopus.com/blog/maven-versioning-explained).
Example version types include `maven`, `python`, `rpm`, and `semver`.
Another version type is `git`, described later.

The version type `custom` is also defined, to mean an otherwise unspecified ordering,
specific to the vendor or product. Using `custom` means that the version status
algorithm cannot be executed, so its use is discouraged; it is included in order
to be able to convert older CVE data that had no concept of version type.

In any version range, the details of the version syntax and semantics depend on the version type,
but by convention, `"version": "0"` means that the range has no lower bound,
and a `*` in an upper bound denotes “infinity”,
as in `"lessThan": "2.*"`, which denotes a range where the 2.X version series is the upper bound,
or `"lessThan": "*"`, which denotes a range with no upper bound at all.

Note that `*` is “infinity”, not a wildcard pattern. For example,

	{
		"version": "1.0",
		"versionType": "semver",
		"lessThan": "2.*",
		"status": "affected"
	}

says that the entire 1.X and 2.X version series are affected.

We saw above the example of a product in which 2.0.0 up to but not including 2.5.2 are affected,
which we wrote as:

	"versions": [
		{ ... 2.0.0 through 2.5.1 affected ... },
		{ ... 2.5.2 through 2.x.x unaffected ... }
	]

Now that we know how to encode version objects, that would be written as:

	"versions": [
		{
			"version": "2.0.0", "versionType": "semver", "lessThan": "2.5.2",
			"status": "affected"
		},
		{
			"version": "2.5.2", "versionType": "semver", "lessThan": "2.*",
			"status": "unaffected"
		}
	]

## Version Status Changes

As presented in the previous section,
a version object's range form (with `versionType` and `lessThan` or `lessThanOrEqual`)
specifies a single status for every version in the range it describes.
It is also possible for the version object to indicate status changes at
transition points, breaking the range up into segments with different status.
This allows a compact way to explain the full status of a particular version branch.

Using status changes, the previous example can be shortened to a single version object:

	"versions": [
		{
			"version": "2.0.0", "versionType": "semver", "lessThan": "2.*",
			"status": "affected",
			"changes": [
				{"at": "2.5.2", "status": "unaffected"}
			]
		}
	]

Note that in this form, the version 2.5.2 is no longer listed twice.

A more complex situation, such as when 2.6.0 had also been released with the vulnerability
and was fixed in 2.6.3, is also easily encoded:

	"versions": [
		{
			"version": "2.0.0", "versionType": "semver", "lessThan": "2.*",
			"status": "affected",
			"changes": [
				{"at": "2.5.2", "status": "unaffected"},
				{"at": "2.6.0", "status": "affected"},
				{"at": "2.6.3", "status": "unaffected"}
			]
		}
	]

When a version is matched by a version range object `entry`,
we have assumed until now that its status is `entry.status`.
With the addition of status changes, the computation of the status
of a matching version is:

	status = entry.status
	for change in entry.changes, sorted in increasing order {
		if change.at ≤ V {
			status = change.status
		}
	}
	return status

For any versioning system with a strict linear ordering (including semantic versioning),
a status change form can always be rewritten into an equivalent, longer list of version objects
without status changes.
Status changes become particularly important for non-linear versions,
such as in source control systems.

## Source Control Versions

For vulnerabilities in open-source software, it can be very helpful to list the
precise changes that introduced and fixed the vulnerability.
To allow this, ranges using `versionType` set to `git` (or `hg` and so on)
can use version control identifiers, such as Git commit hashes,
as version strings.

The previous example might add the source control information to the
`versions` list as follows:

	"versions": [
		{
			"version": "2.0.0", "versionType": "semver", "lessThan": "2.*",
			"status": "affected",
			"changes": [
				{"at": "2.5.2", "status": "unaffected"},
				{"at": "2.6.0", "status": "affected"},
				{"at": "2.6.3", "status": "unaffected"}
			]
		},
		{
			"version": "0", "versionType": "git", "lessThan": "*",
			"repo": "https://github.com/example/test",
			"status": "unaffected",
			"changes": [
				{"at": "123abc...", "status": "affected"},
				{"at": "234bcd...", "status": "unaffected"},
				{"at": "567ef0...", "status": "unaffected"}
			]
		}
	]

Note that the list now contains two different kinds of version information:
semantic versions that users are likely to see
as well as Git commit hashes that are more useful to developers trying to
understand the vulnerability.

Focusing on the Git version range,
the overall range is written to match all Git commits,
declaring them `unaffected` unless specified otherwise by status changes.
(The conventional `0` and `*` specify
“no lower bound, no upper bound” for the range.)
Because the Git version identifiers cannot be understood without
reference to a specific Git repository, this form adds a new `repo` field
containing the URL of the repository. Let's suppose the repository's commit
graph looks like this:

	            1.0.0           1.0.3
	              ↓               ↓
	          o---o---o---o---o---o---o---o ← 012fab...
	         /
	        /                   2.5.1       2.5.2
	       /                      ↓           ↓
	      /               o---o---o---o---o---o---o---o ← 345cde...
	     / 123abc...     /                ↑
	    /      ↓        /             234bcd...
	---o---o---o---o---o ← 2.0.0
	                    \         456def...       567ef0...
	                     \            ↓               ↓
	                      o---o---o---o---o---o---o---o---o---o---o ← 678f01...
	                              ↑           ↑               ↑
	                            2.6.0       2.6.2           2.6.3

In the graph, time moves left to right: if a commit A (denoted by an `o`)
is connected by one or more lines to another commit B to the right of A,
then A is an _ancestor_ of B, and B is a _descendant_ of A.
For source control version types, the less than operator on versions
A \< B is defined to mean that A is an ancestor of B in the commit graph,
and similarly A ≤ B means that A = B or A \< B.
The complete set of less-than relations between the pictured commits is:

 - `123abc...` \< `234bcd...`, `345cde...`, `456def...`, `567ef0...`, and `678f01...`.
 - `234bcd...` \< `345cde...`.
 - `456def...` \< `567ef0...` and `678f01...`.
 - `567ef0...` \< `678f01...`.

The matching and status algorithms then proceed as before,
using that definition of \<.
The iteration “in sorted order” allows any topological sort:
when A \< B, then a status change at A
must be considered before a status change at B.
In this example, the changes list can be processed in two
possible orders: `123abc...` must be first, and then the
other two can be considered in either order,
since neither is less than the other.

Given this repository graph and the source control version information,
we can see exactly what happened with this vulnerability:

 - It was introduced in `123abc...` (released in 2.0.0).
 - It was fixed in `234bcd...` (between 2.5.1 and 2.5.2 on the 2.5 branch).
 - It was fixed in `567ef0...` (between 2.6.2 and 2.6.3 on the 2.6 branch).

The status change list specifies these exact events, which makes it possible
for us to decide whether any given commit has the vulnerability.
For example:

 - `012fab...` is unaffected: it is not a descendant of `123abc...`.
 - `345cde...` is unaffected: it is a descendant of `123abc...` but also of `234bcd...`.
 - `456def...` is affected: it is a descendant of `123abc...` and not a descendant of `234bcd...` or `567ef0...`.

Given this kind of precise source control-level information about which changes
introduced and fixed a vulnerability, it is possible to derive the
affected version ranges automatically.
The [OSV project](https://osv.dev/) is building tooling to do exactly that.

When the `lessThan` field in a source control range is set to something other than `*`,
it has the effect of limiting the commits to which the range applies
to just those commits with `lessThan` as a descendant.
This is typically not useful, but it does allow encoding the
(unusual) practice of issuing different CVEs for different version branches.
For example, if the 2.5 branch and 2.6 branch instances of this
vulnerability needed to be in two different CVE entries, they could be
encoded by giving the CVE for the 2.5 branch this information:

	"defaultStatus": "unaffected"
	"versions": [
		{
			"version": "123abc...", "versionType": "git", "lessThan": "234bcd...",
			"status": "affected"
		}
	]

And by giving the CVE for the 2.6 branch this information:

	"defaultStatus": "unaffected"
	"versions": [
		{
			"version": "123abc...", "versionType": "git", "lessThan": "567ef0...",
			"status": "affected"
		}
	]

Again, this is an unusual choice and should typically be discouraged.
It is more useful in many ways to have a single CVE for each vulnerability.

## Version Objects

For reference, here are all the fields defined for version objects:

 - `version`: the single version being described,
   or the version at the start of the range.
   By convention, `0` typically denotes the earliest possible version.

 - `versionType`: the version numbering system used for specifying the range.
   This defines the exact semantics of the comparison (\< and ≤) operations
   on versions, which is necessary to understand the range itself.
   The value `custom` indicates that the version type is unspecified,
   which should be avoided whenever possible:
   it is included primarily for use in conversion of older data files.

 - `lessThan` or `lessThanOrEqual`: the upper limit of the range.
   Only one of these can be specified.
   For `lessThan`, the least version _not_ in the range.
   For `lessThanOrEqual`, the greatest version in the range;
   this form is discouraged in favor of writing `lessThan`
   with the version that introduced the fix.

   When using `lessThan` (only), the usual version syntax
   is expanded to allow a pattern
   to end in an asterisk (`*`), indicating an arbitrarily large number
   in the version ordering.
   For example, `"lessThan": "1.*"` describes the remainder of the 1.X branch,
   while `"lessThan": "*"` describes all versions greater than or equal to
   the base `version`.

 - `status`: the vulnerability status for the version or range of versions.
   For a range, the status may be refined by the 'changes' list.

 - `changes`: a list of status changes that take place during a range.
   The list should be sorted in (linearly or topologically)
   increasing order by the 'at' field, according to the `versionType`,
   but clients must not assume this.
   Instead, clients must re-sort the list themselves before using it.

A version object describing a single version must specify
both `version` and `status`, and no other fields.

A version object describing a range must specify
`version`, `versionType`, one of `lessThan` or `lessThanOrEqual`, and `status`.
The `changes` field is optional.

Each change object in the `changes` list has two fields:

 - `at`: the version at which a status change occurs.

 - `status`: the new status in the range starting at the given version.

