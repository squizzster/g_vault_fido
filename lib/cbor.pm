package cbor;
use strict;
use warnings;
use CBOR::XS ();

my $CBOR = new_safe CBOR::XS;

sub encode {
    my ($v) = @_; return unless defined $v;
    eval { $CBOR->encode($v) } || undef;
}

sub decode {
    my ($bytes) = @_; return unless defined $bytes && length $bytes;
    eval { $CBOR->decode($bytes) } || undef;
}

1;
