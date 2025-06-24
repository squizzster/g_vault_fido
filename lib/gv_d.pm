package gv_d;
use v5.14;
use strict;
use warnings;

use Crypt::AuthEnc::ChaCha20Poly1305 qw(chacha20poly1305_decrypt_verify);
use Crypt::Digest::BLAKE2b_512       qw(blake2b_512);

use constant {
    MASTER_SECRET_LEN           => 32,
    DYNAMIC_SALT_LEN            => 64,
    MAC_OUTPUT_LEN              => 16,
    RUN_TIME_KEY_LEN            => 32,
    NAME_HASH_HEX_LEN           => 64,
    ERR_DECRYPTION_FAILED       => 'Decryption failed.',
    ERR_INVALID_INPUT           => 'Invalid input provided.',
    ERR_INTERNAL_STATE          => 'Internal state error detected.',
    ERR_RING_NOT_AVAILABLE      => 'Ring not loaded.',
    BLAKE_AAD_TAG               => pack("H*", '83cddaa3fbfcabc498527218b3fa4aa6'),
};

#────────────────────────────────────────────────────────────────────
sub decrypt {
    my %a = @_==1 ? %{$_[0]} : @_;
    my ($blob,$rtk,$aad) = @a{qw(cipher_text run_time_key aad)};
    $aad //= '';

    # Domain tag for AAD
    my $aad_hashed = Crypt::Digest::BLAKE2b_512::blake2b_512(BLAKE_AAD_TAG . $aad);

    return (undef,ERR_INVALID_INPUT) unless defined $blob;
    return (undef,ERR_INVALID_INPUT) unless defined($rtk) && length($rtk)==RUN_TIME_KEY_LEN;

    my $min = NAME_HASH_HEX_LEN + DYNAMIC_SALT_LEN + 12 + 16;
    return (undef,ERR_INVALID_INPUT) if length($blob) < $min;

    my $name_hash = substr($blob,0,NAME_HASH_HEX_LEN,'');
    my $salt      = substr($blob,0,DYNAMIC_SALT_LEN,'');
    my $nonce     = substr($blob,0,12,'');
    my $tag       = substr($blob,-16,16,'');
    my $ct        = $blob;

    return (undef,ERR_RING_NOT_AVAILABLE) if not gv_l::is_loaded_ring($name_hash);

    my ($k, $nck);

    eval {
        ($k, $nck) = @{ gv_e::_derive_for_aead(
            gv_e::_recover_for_mac(
                gv_l::get_cached_ring($name_hash),
                $salt,
                $rtk
            ),
            $salt,
            $rtk
        ) };
        1;  # returns true on success
    } or do {
        return (undef,ERR_DECRYPTION_FAILED);
    };

    return (undef,ERR_DECRYPTION_FAILED) if $nck ne $nonce;

    my $pt;
    eval { $pt = chacha20poly1305_decrypt_verify($k,$nonce,$aad_hashed,$ct,$tag); 1 }
        or return (undef,ERR_DECRYPTION_FAILED);

    return ($pt,undef);
}
1;
