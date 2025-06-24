package gv_m;
use v5.14;
use strict;
use warnings;

use Crypt::Digest::BLAKE2b_256 qw(blake2b_256 blake2b_256_hex);

use constant {
    DYNAMIC_SALT_LEN       => 64,
    RUN_TIME_KEY_LEN       => 32,
    NAME_HASH_HEX_LEN      => 64,
    TAG_LEN                => 16,  # 128-bit tag
    SIG_TAG                => pack("H*", 'b63fd8fbb1e57511f1a261e452e0bea0'),
    ERR_INVALID_INPUT      => 'Invalid input.',
    ERR_RING_NOT_AVAILABLE => 'Ring not loaded.',
    ERR_SIGNATURE_INVALID  => 'Signature invalid.',
};

sub sign {
    my %a = @_ == 1 ? %{ $_[0] } : @_;
    my ($msg, $rtk, $name) = @a{qw(message run_time_key key_name)};

    return ('', ERR_INVALID_INPUT)
        unless defined $msg && defined $rtk && defined $name && length($rtk) == RUN_TIME_KEY_LEN;

    my $name_hash = Crypt::Digest::BLAKE2b_256::blake2b_256_hex($name . gv_e::BLAKE_NAME_TAG());
    my $ring      = gv_l::get_cached_ring($name_hash) or return ('', ERR_RING_NOT_AVAILABLE);
    my $salt      = gv_random::get_crypto_secure_prng(DYNAMIC_SALT_LEN);

    my ($sm) = gv_e::_recover_for_mac($ring, $salt, $rtk);
    return ('', ERR_INVALID_INPUT) unless defined $sm;

    my ($k) = @{ gv_e::_derive_for_mac($sm, $salt, $rtk) || [] };
    my $tag = substr(blake2b_256(SIG_TAG . $msg, $k // ''), 0, TAG_LEN);

    return ($name_hash . $salt . $tag, undef);
}


sub verify {
    my %a = @_ == 1 ? %{ $_[0] } : @_;

    my ($msg, $blob, $rtk) = @a{qw(message signature_blob run_time_key)};

    return (undef, ERR_INVALID_INPUT) unless defined $msg && defined $blob && defined $rtk && length($rtk) == RUN_TIME_KEY_LEN;
    return (undef, ERR_INVALID_INPUT) if length($blob) < NAME_HASH_HEX_LEN + DYNAMIC_SALT_LEN + TAG_LEN;

    my $name_hash = substr( $blob, 0, NAME_HASH_HEX_LEN, '' );
    my $salt      = substr( $blob, 0, DYNAMIC_SALT_LEN,  '' );
    my $tag       = substr( $blob, 0, TAG_LEN,           '' );

    return (substr(
        blake2b_256(SIG_TAG . $msg,
            ( @{ gv_e::_derive_for_mac(
                gv_e::_recover_for_mac(
                    gv_l::get_cached_ring($name_hash) || [], $salt, $rtk
                ) || [], $salt, $rtk
            ) || [] } )[0] // ''
        ),
        0, TAG_LEN
    ) eq $tag) ? 1 : 0;
}

1;
