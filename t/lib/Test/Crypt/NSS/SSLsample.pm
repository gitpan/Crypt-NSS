package Test::Crypt::NSS::SSLsample;

use strict;
use warnings;

use File::Spec;
use Test::Builder;

require Exporter;
our @ISA = qw(Exporter);

our @EXPORT = qw(start_ssl_server);
our @EXPORT_OK = @EXPORT;

my $Tester = Test::Builder->new();
my $Pid;

sub start_ssl_server {
    my %args = @_;
    
    my $bin = File::Spec->catfile($ENV{NSS_BASE}, "bin", "server");
    unless (-e $bin) {
        $Tester->skip_all(q{Can't find ${NSS_BASE}/bin/server});
    }
    
    $Pid = fork();
    $Tester->skip_all(q{Fork failed}) unless defined $Pid;

    if ($Pid) {
        sleep 1;
        return;
    }

    my @args;
    
    # rsa nickname
    push @args, "-n", (exists $args{nickname} ? $args{nickname} : "127.0.0.1");
    
    # port
    push @args, "-p", ($args{port} || 4433);
    
    # db
    push @args, "-d", (exists $args{config_dir} ? $args{config_dir} : "db");
    
    # password
    push @args, "-w", (exists $args{password} ? $args{password} : "crypt-nss");
    
    # certs
    push @args, "-R" if $args{request_cert};    
    push @args, "-F" if $args{require_cert};
    
    close *STDERR;
    close *STDOUT;
    exec($bin, @args);
}

END {
    kill $Pid if $Pid;
}

1;
__END__
