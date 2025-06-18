package gv_random;
use strict;
use warnings;
use Crypt::PRNG ();  # Cryptographically secure random number generator
use Crypt::Digest::BLAKE2b_256   qw(blake2b_256);

# === 1) Crypto-graphically SECURE PRNG ===
my $crypto_secure_prng = Crypt::PRNG->new();    # auto-seeded from /dev/urandom

sub get_crypto_random_bytes {
    my ($no_of_bytes) = @_;
    return $crypto_secure_prng->bytes($no_of_bytes);
}


sub get_bytes {
    my ($no_of_bytes) = @_;
    return if not $no_of_bytes;
    return get_crypto_random_bytes($no_of_bytes);
}

sub get_b58f {
    my ($no_of_bytes) = @_;
    return if not $no_of_bytes;
    return b58f::encode( get_crypto_random_bytes($no_of_bytes) );
}


# === 2) Deterministic random bytes

sub get_seeded_bytes {
    my ($seed, $nbytes) = @_;
    return unless defined $seed;
    return unless $nbytes;

    # Initialize a new PRNG for this seed each time
    my $seeded_prng = Crypt::PRNG->new('ChaCha20', $seed);
    return $seeded_prng->bytes($nbytes);
}
1;
