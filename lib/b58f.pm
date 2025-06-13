package b58f;

use strict;
use warnings;
use Crypt::Misc   ();

sub encode {
    my ($bytes) = @_;
    return unless defined $bytes && length($bytes);
    return Crypt::Misc::encode_b58f($bytes);
}

sub decode {
    my ($bytes) = @_;
    return unless defined $bytes && length($bytes);
    return Crypt::Misc::decode_b58f($bytes);
}

1;
