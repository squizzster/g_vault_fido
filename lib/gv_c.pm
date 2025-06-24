package gv_c;
use v5.14;
use strict;
use warnings;

#######################################################################
# Dependencies
#######################################################################
use Crypt::Digest::BLAKE2b_256 qw(blake2b_256 blake2b_256_hex);
use Crypt::Digest::BLAKE2b_512 ();    # only for side-channel-free RNG seeding in gv_random
use Crypt::Mode::CBC;
use Scalar::Util            qw(weaken);

#######################################################################
# Constants
#######################################################################
use constant {
    MASTER_SECRET_LEN => 32,
    MAC_KEY_LEN       => 32,
    MAC_OUTPUT_LEN    => 16,   # 128-bit tag
    AES_KEY_LEN       => 32,   # AES-256
    AES_IV_LEN        => 16,
    BLAKE_NAME_TAG    => pack('H*', 'ee4bcef77cb49c70f31de849dccaab24'),
    BLAKE_MASTER_TAG  => pack('H*', '915196c5c43ca9a1da54cdce59804793'),
};

#######################################################################
# Deterministic permutation helper
#   Given $key (scalar of any length) and N, returns an array @perm
#   such that @perm is a permutation of 0 .. N-1.
#######################################################################
sub _deterministic_perm {
    my ($key, $n) = @_;
    my @pairs = map {
        # Calculate 128-bit prefix of BLAKE2b(key ‖ “PERM” ‖ i32be)
        my $h = substr blake2b_256($key . "PERM" . pack('N', $_)), 0, 16;
        [ $h, $_ ]
    } 0 .. $n - 1;

    # Sort by hash; extract original indices.
    return map { $_->[1] } sort { $a->[0] cmp $b->[0] } @pairs;
}

#######################################################################
# Helper: best-effort zeroiser (Perl offers no strong guarantees)
#######################################################################
sub _wipe    { return unless defined $_[0]; substr($_[0], $_, 1, "\0") for 0 .. length($_[0]) - 1; $_[0] = undef }
sub _wipe_sv { _wipe(${ $_[0] }) }

#######################################################################
# Internal mini-DSL transform (obfuscation permutation) – unchanged
#######################################################################
my $_apply = sub {
    my ( $m, $p, $b ) = @_;
    return ( $b ^ $p )                                        if $m == 0;
    return ( ( $b << $p ) | ( $b >> ( 8 - $p ) ) ) & 0xFF     if $m == 1;
    return ( $b + $p ) & 0xFF                                 if $m == 2;
    return (~$b) & 0xFF;                                      ## $m == 3; # THIS IS CORRECT.
};

#######################################################################
# build_cipher_ring( name => $text, [ master_secret => $512_bytes ] )
#   → ( $ring_obj , undef | $err )
#######################################################################
sub build_cipher_ring {
    print STDERR "\n\n\n\n\n\n\n build \n\n\n\n\n";
    my (%a)   = @_;
    my $name  = $a{name} // 'default';

    # -- master secret -------------------------------------------------
    my $master = $a{master_secret}
        ? Crypt::Digest::BLAKE2b_256::blake2b_256( $a{master_secret} . BLAKE_MASTER_TAG )
        : gv_random::get_crypto_secure_prng( MASTER_SECRET_LEN );

    return ( undef, 'Master secret wrong length ' . length($master) )
        unless length $master == MASTER_SECRET_LEN;

    # -- static derivations --------------------------------------------
    my $name_hash_hex = blake2b_256_hex( $name . BLAKE_NAME_TAG );
    my $mac_key       = gv_random::get_crypto_secure_prng( MAC_KEY_LEN );
    my $aes_key       = substr blake2b_256( $master . 'AES_KEY' ), 0, AES_KEY_LEN;

    # AES-CBC engine (stateless)
    my $cbc = Crypt::Mode::CBC->new( 'AES', 1 );          # PKCS#7 padding

    # -- node generation – *independent* IV per node -------------------
    my @iv;              # fresh random IV for every node
    my ( @ciphertext, @mac );

    my @bytes = unpack 'C*', $master;
    for my $i ( 0 .. $#bytes ) {

        # ❶ Generate a brand-new IV – no chaining
        $iv[$i] = gv_random::get_crypto_secure_prng( AES_IV_LEN );

        my $seed                = substr blake2b_256( $master . pack( 'N', $i ) ), 0, 2;
        my ( $mr, $pr )         = unpack 'CC', $seed;
        my $mode                = $mr % 4;
        my $param               = $mode == 1 ? 1 + ( $pr % 7 ) : $pr;
        $param                  = 0 if $mode == 3;

        my $stored              = $_apply->( $mode, $param, $bytes[$i] );
        my $plain               = pack 'nC3', $i, $stored, $mode, $param;

        my $ct                  = $cbc->encrypt( $plain, $aes_key, $iv[$i] );

        # ❷ MAC covers IV‖CT (tag still truncated to 128 bits)
        my $tag                 = substr blake2b_256(
                                    $mac_key . $iv[$i] . $ct
                                  ), 0, MAC_OUTPUT_LEN;

        push @ciphertext, $ct;
        push @mac,        $tag;
    }

    ###################################################################
    # Fisher–Yates shuffle – deterministic permutation
    ###################################################################
    my @perm = _deterministic_perm(
        Crypt::Digest::BLAKE2b_512::blake2b_512( $name . $master ),
        scalar @ciphertext
    );

    @ciphertext   = @ciphertext[ @perm ];
    @mac          = @mac[         @perm ];
    @iv           = @iv[          @perm ];     # keep IV ↔ node alignment

    ###################################################################
    # Relink, build closures, assemble ring (unchanged below)
    ###################################################################
    my ( @closures, @next_ref, @next_iv_ref );
    for my $idx ( 0 .. $#ciphertext ) {

        my ( $ct, $tag, $this_iv ) = ( $ciphertext[$idx], $mac[$idx], $iv[$idx] );
        my ( $next, $next_iv );                       # will be set after relink

        push @next_ref,    \$next;
        push @next_iv_ref, \$next_iv;

        push @closures, sub {
            my ($raw) = @_;

            return (
                index     => $idx,
                iv        => $this_iv,
                ct        => $ct,
                tag       => $tag,
                next_node => $next,
                next_iv   => $next_iv,
            ) if defined $raw && $raw eq 'raw';

            # authenticated decrypt – *die* on failure
            my $calc = substr blake2b_256( $mac_key . $this_iv . $ct ), 0, MAC_OUTPUT_LEN;
            return ( undef, 'MAC mismatch in node' ) if $calc ne $tag;

            my $plain = $cbc->decrypt( $ct, $aes_key, $this_iv );
            my ( $i, $stored_byte, $mode, $param ) = unpack 'nC3', $plain;
            substr( $plain, $_, 1, "\0" ) for 0 .. length($plain) - 1;  # best-effort wipe

            return (
                index       => $i,
                stored_byte => $stored_byte,
                mode        => $mode,
                param       => $param,
                next_node   => $next,
                next_iv     => $next_iv,
            );
        };
    }

    # ── Build Hamiltonian cycle in the permuted order ────────────────
    for my $i ( 0 .. $#closures ) {
        my $succ = ( $i + 1 ) % @closures;

        ${ $next_ref[$i] }    = $closures[$succ];
        weaken( ${ $next_ref[$i] } );
        ${ $next_iv_ref[$i] } = $iv[$succ];
    }

    ###################################################################
    # Final ring object
    ###################################################################
    return (
        {
            f         => $closures[0],        # random entry point
            name      => $name,
            name_hash => $name_hash_hex,
            mac_key   => $mac_key,
            aes_key   => $aes_key,
            nodes     => [ @closures ],
        },
        undef
    );
}

1; # end of gv_c.pm
