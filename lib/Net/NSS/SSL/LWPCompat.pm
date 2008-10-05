package Net::NSS::SSL::LWPCompat;

use strict;
use warnings;

use Symbol;
use Net::NSS::SSL;

my %Socket;

sub new {
    my $pkg = shift;
    my $socket = Net::NSS::SSL->new(@_);

    my $self = Symbol::gensym();
    bless $self, $pkg;
    
    $Socket{$self} = $socket;
    
    return $self;
}

sub DESTROY {
    my $self = shift;
    delete $Socket{$self};
}

sub syswrite {
    my $self = shift;
    my $data = shift;
    $Socket{$self}->syswrite($data);
}

sub sysread {
    my $self = shift;
    $Socket{$self}->sysread($_[0], $_[1]);
}

for my $meth (qw(peerhost peerport get_peer_certificate get_cipher)) {
    no strict 'refs';
    *$meth = sub {
        my $self = shift;
        $Socket{$self}->$meth();
    };
}

1;
__END__

=head1 NAME

Net::NSS::SSL::LWPCompat - Wrapper for Net::NSS::SSL to make it LWP compatible

=head1 SYNOPSIS

  # Using NSS for SSL connections from LWP
  use LWP;
  use Crypt::NSS config_dir => "$ENV{HOME}/.netscape";
  use Net::HTTPS;
  
  local @Net::HTTPS::ISA = qw(Net::NSS::SSL::LWPCompat Net::HTTP::Methods);
  
  my $content = get("https://secure.mycompany.com");

=head1 INTERFACE

=head2 CLASS METHODS

=over 4

=item new ( $addr : string, %args )

=item new ( %args )

See L<Net::NSS::SSL/new>

=back

=head2 INSTANCE METHODS

=over 4

=item get_cipher

L<Net::NSS::SSL/get_cipher>

=item get_peer_certificate

L<Net::NSS::SSL/get_peer_certificate>

=item peerhost

L<Net::NSS::SSL/peerhost>

=item peerport

L<Net::NSS::SSL/peerport>

=item sysread

L<Net::NSS::SSL/sysread>

=item syswrite

L<Net::NSS::SSL/syswrite>

=cut