#!/usr/bin/perl -w
#
# Convert CNA assignment information in CSV or flat file format to JSON.
#
# Copyright (C) The MITRE Corporation.


######################################################################
use strict;
use Getopt::Long;
use JSON::XS;
use Text::CSV_XS;



######################################################################
# Initialize variables.
$| = 1;

my $cve_pat = qr/CVE-[12]\d{3}-\d{4,}/;

my $data_version = "4.0";
my @supported_data_versions = (
  $data_version,
);

# Set the assigner and vendor, then remove the "die" line below.
die "\$assigner and \$vendor variables need to be configured!";
my $assigner = '*** unspecified ***';                       # e-mail address for the security PoC.
my $vendor = '*** unspecified ***';                         # vendor name.


######################################################################
# Process commandline arguments.
my %options = (
  'spec' => \$data_version,
);
Getopt::Long::Configure('bundling');
GetOptions(
  \%options,
  "help|h|?!",
  "files|f!",
  "spec|s=s",
  "vendor|v=s",
) or $options{help} = 1;
$0 =~ s/^.+\///;
if ($options{help} or @ARGV > 0)
{
  warn "\n" .
       "Usage: $0 [options]\n" .
       "\n" .
       "Converts CVE assignment information from STDIN to JSON.\n" . 
       "\n" .
       "Options :\n" .
       "  -?, -h, --help                Display this help and exit.\n" .
       "  -f, --files                   Write output to individual files instead of to STDOUT.\n" .
       "  -s, --spec <spec>             Output JSON that conforms to specified specification (defaults to $data_version).\n" .
       "  -v, --vendor <vendor>         Use <vendor> as the specified vendor instead of '$vendor'.\n";
  exit 1;
}

$vendor = $options{vendor} if (exists $options{vendor});



######################################################################
# Process input.
my $json = new JSON::XS;
my @data;

my $csv = Text::CSV_XS->new({ binary => 1, allow_whitespace => 1 });
my $contents = do { local $/; <> };

my @lines = split(/\n/, $contents);
my $input_fmt = ($lines[0] =~ /^\s*\[CVEID\]/ ? "multi-line" : "csv");

my $l = 0;
while (@lines)
{
  my $line = shift @lines;
  $l++;

  next unless $line =~ /\S/;

  my($id, $product, $version, $problem_type, @urls, $description);

  if ($input_fmt eq "csv")
  {
    unless ($csv->parse($line))
    {
      warn "Failed to parse line $l - " . $csv->error_input() . "\n";
      next;
    }
    my @fields = $csv->fields();
    unless (@fields == 6)
    {
      warn "Unexpected number of fields in line $l!\n";
      next;
    }
    $id = $fields[0];
    $product = $fields[1];
    $version = $fields[2];
    $problem_type = $fields[3];
    push(@urls, split(/\s+/, $fields[4]));
    $description = $fields[5];
  }
  else
  {
    die "*** Invalid content in line $l ($line)! ***\n" unless ($line =~ /^\s*\[CVEID\]\s*:\s*(.+?)\s*$/);
    $id = $1;

    $line = shift @lines or die "*** Incomplete entry for $id at line $l! ***\n";
    $l++;
    die "*** Invalid content in line $l ($line)! ***\n" unless ($line =~ /^\s*\[PRODUCT\]\s*:\s*(.+?)\s*$/);
    $product = $1;

    $line = shift @lines or die "*** Incomplete entry for $id at line $l! ***\n";
    $l++;
    die "*** Invalid content in line $l ($line)! ***\n" unless ($line =~ /^\s*\[VERSION\]\s*:\s*(.+?)\s*$/);
    $version = $1;

    $line = shift @lines or die "*** Incomplete entry for $id at line $l! ***\n";
    $l++;
    die "*** Invalid content in line $l ($line)! ***\n" unless ($line =~ /^\s*\[PROBLEMTYPE\]\s*:\s*(.+?)\s*$/);
    $problem_type = $1;

    $line = shift @lines or die "*** Incomplete entry for $id at line $l! ***\n";
    $l++;
    die "*** Invalid content in line $l ($line)! ***\n" unless ($line =~ /^\s*\[REFERENCES\]\s*:\s*(.+?)\s*$/);
    @urls = split(/\s+/, $1);

    $line = shift @lines or die "*** Incomplete entry for $id at line $l! ***\n";
    $l++;
    die "*** Invalid content in line $l ($line)! ***\n" unless ($line =~ /^\s*\[DESCRIPTION\]\s*:\s*(.+?)\s*$/);
    $description = $1;
  }
  $id =~ s/^\s+|\s+$//g;
  $product =~ s/^\s+|\s+$//g;
  $version =~ s/^\s+|\s+$//g;
  $problem_type =~ s/^\s+|\s+$//g;
  $description =~ s/^\s+|\s+$//g;

  unless ($id =~ /^$cve_pat$/)
  {
    warn "ignored - '$id' is not a valid CVE id.\n";
    next;
  }

  my $datum;
  if ($data_version == "4.0")
  {
    $datum->{data_type} = "CVE";
    $datum->{data_format} = "MITRE";
    $datum->{data_version} = $data_version;
    $datum->{CVE_data_meta} = {
      'ID' => $id,
    };

    $datum->{problemtype} = {
      "problemtype_data" => [
        {
          "description" => [
            {
              "lang" => "eng",
              "value" => "$problem_type",
            },
          ],
        },
      ],
    };

    my @version_objs;
    foreach my $v (split /\s*;\s*/, $version)
    {
      $v =~ s/^\s*and\s+(\S)/$1/;
      $v =~ s/^\s+|\s+$//g;
      push(@version_objs, { "version_value" => $v });
    }

    $datum->{affects} = {
      "vendor" => {
        "vendor_data" => [
          {
            "vendor_name" => "$vendor",
            "product" => {
              "product_data" => [
                {
                  "product_name" => "$product",
                  "version" => {
                    "version_data" => [
                       @version_objs
                    ],
                  },
                },
              ],
            },
          },
        ],
      },
    };

    $datum->{CVE_data_meta}->{ASSIGNER} = $assigner;

    $datum->{CVE_data_meta}->{STATE} = "PUBLIC";

    $datum->{description} = {
      'description_data' => [ 
        {
          "value" => $description,
          "lang" => "eng",
        }
      ],
    };

    foreach my $url (@urls)
    {
      my $ref_obj = {
        "url" => $url,
      };
      push(@{$datum->{references}->{reference_data}}, $ref_obj);
    }
  }

  if ($options{files})
  {
    my $file = $id . ".json";
    my $fh;
    unless (open $fh, ">:encoding(UTF-8)", "$file")
    {
      warn "Failed to write to '$file' - $!\n";
      next;
    }
    print $fh $json->canonical(1)->pretty(1)->encode($datum);
    close($fh);
  }
  else
  {
    push(@data, $datum);
  }
}
print $json->canonical(1)->pretty(1)->encode(\@data) unless $options{files};

