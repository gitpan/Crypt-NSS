#!/usr/bin/perl

use strict;
use warnings;

use Test::More skip_all => "Server sockets are not implemented yet";
use Test::Exception;

use Crypt::NSS config_dir => "db", cipher_policy => "Export";
use Crypt::NSS::Constants qw(:ssl);

exit;

Crypt::NSS::SSL->config_server_session_cache({
    maxCacheEntries => 10_000,
    ssl2_timeout    => 100,
    ssl3_timeout    => 86400,
    shared          => 0,
});

my $server = Net::NSS::SSL->create_socket("tcp");

lives_ok {
    $server->set_socket_option("Blocking" => 1);
};

lives_ok {
    $server->bind("127.0.0.1", 4433);
};

lives_ok {
    $server->listen();
};


my $client = $server->accept();

$client->import_into_ssl_layer();
lives_ok {
    $client->set_option(SSL_HANDSHAKE_AS_SERVER, 1);
}

