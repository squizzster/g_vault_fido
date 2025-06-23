package gv_m;
use v5.24;
use strict;
use warnings;

use Crypt::Digest::BLAKE2b_256 qw(blake2b_256 blake2b_256_hex);

use constant {
    DYNAMIC_SALT_LEN       => 64,
    PEPPER_LEN             => 32,
    NAME_HASH_HEX_LEN      => 64,
    TAG_LEN                => 16,  # 128-bit tag
    SIG_TAG                => pack("H*", 'b63fd8fbb1e57511f1a261e452e0bea0'),
    ERR_INVALID_INPUT      => 'Invalid input.',
    ERR_RING_NOT_AVAILABLE => 'Ring not loaded.',
    ERR_SIGNATURE_INVALID  => 'Signature invalid.',
};

sub _old_sign {
    my %a = @_ == 1 ? %{ $_[0] } : @_;
    my ($msg, $pep, $name) = @a{qw(message pepper key_name)};

    return (undef, ERR_INVALID_INPUT)
        unless defined $msg && defined $pep && defined $name
           && length($pep) == PEPPER_LEN;

    my $name_hash = Crypt::Digest::BLAKE2b_256::blake2b_256_hex(
        $name . gv_e::BLAKE_NAME_TAG()
    );
    my $ring = gv_l::get_cached_ring($name_hash)
        or return (undef, ERR_RING_NOT_AVAILABLE);

    my $salt = gv_random::get_crypto_secure_prng(DYNAMIC_SALT_LEN);

    my ($sm) = gv_e::_recover_for_mac($ring, $salt, $pep);
    return (undef, 'cycle') if not defined $sm;
    use Data::Dump qw(dump);
    print STDERR ( "PASSWORD [" . ( dump $sm ) . "].\n" );

    my ($k) = @{ gv_e::_derive_for_mac($sm, $salt, $pep) };

    my $tag = substr blake2b_256(SIG_TAG . $msg, $k), 0, TAG_LEN;

    return ($name_hash . $salt . $tag, undef);
}

sub sign {
    my %a = @_ == 1 ? %{ $_[0] } : @_;
    my ($msg, $pep, $name) = @a{qw(message pepper key_name)};

    return ('', ERR_INVALID_INPUT)
        unless defined $msg && defined $pep && defined $name && length($pep) == PEPPER_LEN;

    my $name_hash = Crypt::Digest::BLAKE2b_256::blake2b_256_hex($name . gv_e::BLAKE_NAME_TAG());
    my $ring      = gv_l::get_cached_ring($name_hash) or return ('', ERR_RING_NOT_AVAILABLE);
    my $salt      = gv_random::get_crypto_secure_prng(DYNAMIC_SALT_LEN);

    my ($sm) = gv_e::_recover_for_mac($ring, $salt, $pep);
    return ('', ERR_INVALID_INPUT) unless defined $sm;

    my ($k) = @{ gv_e::_derive_for_mac($sm, $salt, $pep) || [] };
    my $tag = substr(blake2b_256(SIG_TAG . $msg, $k // ''), 0, TAG_LEN);

    return ($name_hash . $salt . $tag, undef);
}


sub verify {
    my %a = @_ == 1 ? %{ $_[0] } : @_;

    my ($msg, $blob, $pep) = @a{qw(message signature_blob pepper)};

    return (undef, ERR_INVALID_INPUT) unless defined $msg && defined $blob && defined $pep && length($pep) == PEPPER_LEN;
    return (undef, ERR_INVALID_INPUT) if length($blob) < NAME_HASH_HEX_LEN + DYNAMIC_SALT_LEN + TAG_LEN;

    my $name_hash = substr( $blob, 0, NAME_HASH_HEX_LEN, '' );
    my $salt      = substr( $blob, 0, DYNAMIC_SALT_LEN,  '' );
    my $tag       = substr( $blob, 0, TAG_LEN,           '' );

    return (substr(
        blake2b_256(SIG_TAG . $msg,
            ( @{ gv_e::_derive_for_mac(
                gv_e::_recover_for_mac(
                    gv_l::get_cached_ring($name_hash) || [], $salt, $pep
                ) || [], $salt, $pep
            ) || [] } )[0] // ''
        ),
        0, TAG_LEN
    ) eq $tag) ? 1 : 0;
}

1;
