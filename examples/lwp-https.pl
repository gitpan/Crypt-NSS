#!/usr/bin/perl

use strict;
use warnings;

use LWP::Simple;
use Net::HTTPS;
use Crypt::NSS config_dir => "db", cipher_suite => "US";

@Net::HTTPS::ISA = qw(Net::NSS::SSL::LWPCompat Net::HTTP::Methods);

Crypt::NSS::PKCS11->set_default_pkcs11_pin_arg("crypt-nss");

my $content = get("https://www.mozilla.org");

print $content;