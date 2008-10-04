#!/usr/bin/perl

use lib "t/lib";
use strict;
use warnings;

use Test::More tests => 11;
use Test::Exception;
use Test::Crypt::NSS::SSLsample;

use Crypt::NSS config_dir => "db", cipher_suite => "US";

start_ssl_server(config_dir => "db", port => 4433, password => "crypt-nss");

my $socket = Net::NSS::SSL->create_socket("tcp");
ok(defined $socket, "Socket is defined");
isa_ok($socket, "Net::NSS::SSL", "Socket is-a Net::NSS::SSL");
ok(!$socket->is_connected);
ok(!$socket->does_ssl);

$socket->set_option(Blocking => 1);
ok($socket->get_option("Blocking"));

$socket->import_into_ssl_layer();

ok($socket->does_ssl);

$socket->set_URL("127.0.0.1");
$socket->set_client_certificate_hook("built-in", "127.0.0.1");
$socket->set_pkcs11_pin_arg("crypt-nss");

lives_ok {
    $socket->connect("127.0.0.1", 4433);
};

my $written = 0;
lives_ok {
    $written = $socket->write("GET / HTTP/1.0\n\n\n\n");
};

is($written, 18, "Wrote request");

my $reply = "";
lives_ok {
    my $buffer;
    while($socket->read($buffer) > 0) {
        $reply .= $buffer;
    }
};

like($reply, qr{<h2>This is your request:</h2><br>GET / HTTP/1.0});

$socket->close();
