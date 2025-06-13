package cbor;

use strict;
use warnings;
use CBOR::XS ();

my $CBOR = new_safe CBOR::XS;

sub encode {
    my ($value) = @_;
    return unless defined $value;
    my $cbor;
    eval { $cbor = $CBOR->encode($value) };
    return unless defined $cbor && !$@;
    return $cbor;
}

sub decode {
    my ($bytes) = @_;
    return unless defined $bytes && length($bytes);
    my $obj;
    eval { $obj = $CBOR->decode($bytes) };
    if ( not defined $obj ) {
        print STDERR ("I COULD NOT DECODE CBOR\n");
    }
    return unless defined $obj && !$@;
    return $obj;
}

1;
