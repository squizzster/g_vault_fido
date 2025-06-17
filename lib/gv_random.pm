package gv_random;
use strict;
use warnings;
use Crypt::PRNG ();  # Cryptographically secure random number generator

sub get_bytes {
    my ($no_of_bytes) = @_;
    return if not $no_of_bytes;
    return Crypt::PRNG::random_bytes($no_of_bytes);
}

sub get_b58f {
    my ($no_of_bytes) = @_;
    return if not $no_of_bytes;
    return b58f::encode( Crypt::PRNG::random_bytes($no_of_bytes) );
}

1;
