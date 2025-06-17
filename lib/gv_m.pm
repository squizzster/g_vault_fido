package gv_m;
use v5.24;
use strict;
use warnings;

use Crypt::Digest::BLAKE2b_256 qw(blake2b_256);
#use gv_l ();              # ring loader / cache
#use gv_e ();              # provides _recover_for_mac and _derive_for_mac

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

#--------------------------------------------------------------------
# sign(
#   message  => $msg,
#   pepper   => $32_byte_secret,
#   key_name => $ring_name
# ) -> ($sig_blob, undef | $err)
#
# sig_blob = hex64-ring-id || raw-64-byte-salt || raw-16-byte-tag
#--------------------------------------------------------------------
sub sign {
    my %a = @_ == 1 ? %{ $_[0] } : @_;
    my ($msg, $pep, $name) = @a{qw(message pepper key_name)};

    return (undef, ERR_INVALID_INPUT)
        unless defined $msg && defined $pep && defined $name
           && length($pep) == PEPPER_LEN;

    # load ring
    my $name_hash = Crypt::Digest::BLAKE2b_256::blake2b_256_hex(
        $name . gv_e::BLAKE_NAME_TAG()
    );
    my $ring = gv_l::get_cached_ring($name_hash)
        or return (undef, ERR_RING_NOT_AVAILABLE);

    # fresh salt per message
    my $salt = gv_random::get_bytes(DYNAMIC_SALT_LEN);

    # derive master-secret and AEAD key
    my ($sm, $er) = gv_e::_recover_for_mac($ring, $salt, $pep);
    return (undef, $er) if $er;
    my ($k) = @{ gv_e::_derive_for_mac($sm, $salt, $pep) };

    # compute 128-bit BLAKE2b MAC
    my $tag = substr blake2b_256(SIG_TAG . $msg, $k), 0, TAG_LEN;

    return ($name_hash . $salt . $tag, undef);
}

#--------------------------------------------------------------------
# verify(
#   message        => $msg,
#   signature_blob => $blob,
#   pepper         => $32_byte_secret
# ) -> (1 | 0, undef | $err)
#--------------------------------------------------------------------
sub verify {
    my %a = @_ == 1 ? %{ $_[0] } : @_;
    my ($msg, $blob, $pep) = @a{qw(message signature_blob pepper)};

    return (undef, ERR_INVALID_INPUT)
        unless defined $msg && defined $blob && defined $pep
           && length($pep) == PEPPER_LEN;

    my $min = NAME_HASH_HEX_LEN + DYNAMIC_SALT_LEN + TAG_LEN;
    return (undef, ERR_INVALID_INPUT) if length($blob) < $min;

    # split blob
    my $name_hash = substr($blob, 0, NAME_HASH_HEX_LEN, '');
    my $salt      = substr($blob, 0, DYNAMIC_SALT_LEN, '');
    my $tag       = substr($blob, 0, TAG_LEN, '');

    # load ring and derive key
    my $ring = gv_l::get_cached_ring($name_hash)
        or return (undef, ERR_RING_NOT_AVAILABLE);
    my ($sm, $er) = gv_e::_recover_for_mac($ring, $salt, $pep);
    return (undef, $er) if $er;
    my ($k) = @{ gv_e::_derive_for_mac($sm, $salt, $pep) };

    # recompute expected tag
    my $expect = substr blake2b_256(SIG_TAG . $msg, $k), 0, TAG_LEN;

    # constant-time compare
    my $diff = 0;
    $diff |= (ord substr($expect, $_, 1)) ^ (ord substr($tag, $_, 1))
        for 0 .. TAG_LEN-1;

    return ($diff == 0 ? 1 : 0,
            $diff == 0 ? undef : ERR_SIGNATURE_INVALID);
}

1;

