package gv_e;
use v5.14;
use strict;
use warnings;
use Scalar::Util qw(refaddr);

use Crypt::AuthEnc::ChaCha20Poly1305 qw(chacha20poly1305_encrypt_authenticate);
use Crypt::KeyDerivation             qw(hkdf);
use Crypt::Digest::BLAKE2b_256       qw(blake2b_256 blake2b_256_hex);
use Crypt::Digest::BLAKE2b_512       qw(blake2b_512);

use constant {
    VERSION                     => 'V1',
};

use constant {
    MASTER_SECRET_LEN           => 32,
    DYNAMIC_SALT_LEN            => 64,
    MAC_OUTPUT_LEN              => 16,
    RUN_TIME_KEY_LEN            => 32,
    NAME_HASH_HEX_LEN           => 64,
    ERR_ENCRYPTION_FAILED       => 'Encryption failed.',
    ERR_INVALID_INPUT           => 'Invalid input provided.',
    ERR_INTERNAL_STATE          => 'Internal state error detected.',
    ERR_RING_NOT_AVAILABLE      => 'Ring not loaded.',
    BLAKE_NAME_TAG              => pack("H*", 'ee4bcef77cb49c70f31de849dccaab24'),
    BLAKE_AAD_TAG               => pack("H*", '83cddaa3fbfcabc498527218b3fa4aa6'),

    # -- Domain Separation Tags for Key Derivation --
    # Binary random prefixes for IKM and Salt
    DS_IKM_AEAD                 => pack( "H*", '944162c236618cab10650605c7181c0c' ),
    DS_IKM_MAC                  => pack( "H*", 'a0d9d7c2483afa20ec7bfcf3759c0229' ), 
    DERIVE_SALT_PREFIX_1        => pack( "H*", 'dfdd2bd94f72efcea506d7257c096dbe' ),
    DERIVE_SALT_PREFIX_2        => pack( "H*", 'd1d608365399edf5a45c3b84e43bbda1' ),
    DERIVE_SALT_PREFIX_3        => pack( "H*", 'a4504b6b21f0835920573bd9f308a1ff' ),

    # Human-readable labels for HKDF 'info' parameter
    DS_INFO_AEAD_KEY            => 'GVAULT::INFO_AEAD_KEY::'   . VERSION,
    DS_INFO_AEAD_NONCE          => 'GVAULT::INFO_AEAD_NONCE::' . VERSION,
    DS_INFO_MAC_KEY             => 'GVAULT::INFO_MAC_KEY::'    . VERSION,
};

my $_undo = sub { my ($m,$p,$b)=@_;
    return ($b ^ $p)                      if $m==0;
    return (($b>>$p)|($b<<(8-$p))) & 0xFF if $m==1;
    return ($b - $p) & 0xFF               if $m==2;
    return (~$b) & 0xFF;
};

# --- faster, zero-copy version -------------------------------------
my $_recover = sub {
    my ($ring, $salt, $rtk) = @_;

    # sanity checks ­­­­­­­­­­­­­­­­­­­­­­­­­­­­­­­­­­­­
    return (undef, 'bad ring')   if not defined $ring or ref($ring) eq 'ARRAY';
    return (undef, 'bad salt')   if length($salt)   != DYNAMIC_SALT_LEN;
    return (undef, 'bad RTK')    if length($rtk) != RUN_TIME_KEY_LEN;

    # unpack salt / run-time-key once
    my @sb = unpack 'C*', $salt;
    my @pb = unpack 'C*', $rtk;

    my %seen;
    my $node = $ring->{f};

    # pre-allocate the MASTER_SECRET_LEN-byte master-secret buffer
    my $secret = "\0" x MASTER_SECRET_LEN;
    my $i      = 0;                          # write index

    while ( $node && !$seen{ refaddr $node }++ ) {
        my %d     = $node->();               # {mode,param,stored_byte,index,next_node}

        unless (%d &&
                defined $d{mode} &&
                defined $d{stored_byte} &&
                defined $d{index} &&
                exists $d{next_node}
               ) {
            return (undef, ERR_INTERNAL_STATE . ' Node recovery failed: Invalid data from node.');
        }

        my $orig  = $_undo->( @d{qw(mode param stored_byte)} );

        # salt- & run-time-key-mix
        my $byte  = $orig
                  ^ $pb[ $d{index} % RUN_TIME_KEY_LEN ]
                  ^ $sb[ $d{index} % DYNAMIC_SALT_LEN ];

        # write straight into buffer (8-bit slot)
        vec( $secret, $i++, 8 ) = $byte;

        $node = $d{next_node};
    }

    return undef unless $i == MASTER_SECRET_LEN;
    return $secret;
};

my $_derive_aead_params = sub {
    my ($sm,$salt,$rtk)=@_;
    return if not defined $sm;
    my $ikm = DS_IKM_AEAD . $sm . $rtk;
    my $k   = hkdf($ikm, DERIVE_SALT_PREFIX_1 . $salt, 'BLAKE2b_256', 32, DS_INFO_AEAD_KEY);
    my $n   = hkdf($ikm, DERIVE_SALT_PREFIX_2 . $salt, 'BLAKE2b_256', 12, DS_INFO_AEAD_NONCE);
    [$k,$n];
};

my $_derive_mac_key = sub {
    my ($sm,$salt,$rtk)=@_;
    return if not defined $sm;
    my $ikm = DS_IKM_MAC . $sm . $rtk;
    my $k   = hkdf($ikm, DERIVE_SALT_PREFIX_3 . $salt, 'BLAKE2b_256', 32, DS_INFO_MAC_KEY);
    [$k];
};


#────────────────────────────────────────────────────────────────────
# expose internal recover+derive closures for downstream use
sub _recover_for_mac { goto &{ $_recover } }
sub _derive_for_mac  { goto &{ $_derive_mac_key } }
sub _derive_for_aead { goto &{ $_derive_aead_params } }


sub encrypt {
    my %a = @_==1 ? %{$_[0]} : @_;
    my ($pt,$rtk,$name,$aad) = @a{qw(plaintext run_time_key key_name aad)};
    $aad //= '';

    # Domain tag for AAD
    my $aad_hashed = Crypt::Digest::BLAKE2b_512::blake2b_512(BLAKE_AAD_TAG . $aad);

    return (undef,ERR_INVALID_INPUT) unless defined $pt;
    return (undef,ERR_INVALID_INPUT) unless defined($rtk) && length($rtk)==RUN_TIME_KEY_LEN;
    return (undef,ERR_INVALID_INPUT) unless defined $name;

    my $name_hash = Crypt::Digest::BLAKE2b_256::blake2b_256_hex($name . BLAKE_NAME_TAG);

    return (undef,ERR_RING_NOT_AVAILABLE) if not gv_l::is_loaded_ring($name_hash);

    my $salt = gv_random::get_crypto_secure_prng(DYNAMIC_SALT_LEN);

    my ($k, $nonce);

    eval {
        ($k, $nonce) = @{ 
            $_derive_aead_params->(
                $_recover->(
                    gv_l::get_cached_ring($name_hash),
                    $salt,
                    $rtk
                ),
                $salt,
                $rtk
            )
        };
        1;  # ensure eval returns true on success
    } or do {
        return (undef,ERR_ENCRYPTION_FAILED);
    };

    my ($ct,$tag);
    eval { ($ct,$tag)=chacha20poly1305_encrypt_authenticate($k,$nonce,$aad_hashed,$pt); 1 }
        or return (undef,ERR_ENCRYPTION_FAILED);

    return ($name_hash.$salt.$nonce.$ct.$tag, undef);
}
1;
