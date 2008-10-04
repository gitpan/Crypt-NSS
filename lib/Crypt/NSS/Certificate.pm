package Crypt::NSS::Certificate;

use strict;
use warnings;

sub is_valid_now {
    my $self = shift;
    my ($sec, $min, $hour, $mday, $month, $year) = (localtime(time))[0..5];
    return $self->get_validity_for_datetime($year + 1900, $month, $mday, $hour, $min, $sec) == 1;
}

1;
__END__

=head1 NAME

Crypt::NSS::Certificate - X.509 certificate and related fuctions

=head1 INTERFACE

=head1 INSTANCE METHODS

=over 4

=item clone ( ) : Crypt::NSS::Certificate

Returns a copy of the certificate.

=item verify_hostname ( HOSTNAME_PATTERN ) : BOOLEAN

Verifies that the hostname in the certificate matches the given hostname pattern.

=back

=cut

