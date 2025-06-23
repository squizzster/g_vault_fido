package gv_aes;
use v5.14;
use strict;
use warnings;
use Crypt::Mode::CBC;

                  #  use Crypt::KeyDerivation             qw(hkdf);
                  #  use Crypt::Digest::BLAKE2b_256       qw(blake2b_256 blake2b_256_hex);
                  #  use Carp qw(croak);
                  #  use gv_random;

use constant {
    PADDING         => 1,
    NO_OF_ROUNDS    => 14,
    VERSION         => 'V1.0',
};

my $g_aes   = Crypt::Mode::CBC->new( 'AES', PADDING, NO_OF_ROUNDS );

sub encrypt {
    return eval { $g_aes->encrypt($_[0], $_[1], $_[2]) } // undef;
}

sub decrypt {
    return eval { $g_aes->decrypt($_[0], $_[1], $_[2]) } // undef;
}

1;
