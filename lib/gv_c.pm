package gv_c;
use v5.14;
use strict;
use warnings;

#######################################################################
# Dependencies
#######################################################################
use Carp                     qw(croak);
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
    my (%a)   = @_;
    my $name  = $a{name} // 'default';

    # -- master secret -------------------------------------------------
    my $master = $a{master_secret}
        ? Crypt::Digest::BLAKE2b_256::blake2b_256($a{master_secret} . BLAKE_MASTER_TAG)
        : gv_random::get_crypto_secure_prng(MASTER_SECRET_LEN);

    return ( undef, 'Master secret wrong length ' . length($master) )
        unless length $master == MASTER_SECRET_LEN;

    # -- static derivations --------------------------------------------
    my $name_hash_hex = blake2b_256_hex( $name . BLAKE_NAME_TAG );
    my $mac_key       = gv_random::get_crypto_secure_prng(MAC_KEY_LEN);
    my $aes_key       = substr blake2b_256( $master . 'AES_KEY' ), 0, AES_KEY_LEN;

    # AES-CBC engine (stateless)
    my $cbc = Crypt::Mode::CBC->new( 'AES', 1 );                # PKCS#7

    # -- node generation ----------------------------------------------
    my $iv0 = gv_random::get_crypto_secure_prng(AES_IV_LEN);
    my @iv  = ( $iv0 );
    my ( @ciphertext, @mac );

    my @bytes = unpack 'C*', $master;
    for my $i ( 0 .. $#bytes ) {
        my $seed                = substr blake2b_256( $master . pack('N', $i) ), 0, 2;
        my ( $mr, $pr )         = unpack 'CC', $seed;
        my $mode                = $mr % 4;
        my $param               = $mode == 1 ? 1 + ( $pr % 7 ) : $pr;
        $param                  = 0 if $mode == 3;
        my $stored              = $_apply->( $mode, $param, $bytes[$i] );

        my $plain               = pack 'nC3', $i, $stored, $mode, $param;
        my $ct                  = $cbc->encrypt( $plain, $aes_key, $iv[$i] );
        my $tag                 = substr blake2b_256( $mac_key . $iv[$i] . $ct ), 0, MAC_OUTPUT_LEN;

        push @ciphertext, $ct;
        push @mac,        $tag;
        $iv[ $i + 1 ]     = substr $ct, 0, AES_IV_LEN;        # IV-chaining
    }

    # -- build closures in sequential order ---------------------------
    my ( @closures, @next_ref, @next_iv_ref );
    for my $idx ( 0 .. $#ciphertext ) {
        my ( $ct, $tag, $this_iv ) = ( $ciphertext[$idx], $mac[$idx], $iv[$idx] );
        my $next_iv                = undef;   # will be filled after shuffling/linking
        my $next                   = undef;   # ditto

        push @next_ref,    \$next;
        push @next_iv_ref, \$next_iv;

        push @closures, sub {
            my ($raw) = @_;

            # ---- raw dump (for serializer) ---------------------------
            if ( defined $raw && $raw eq 'raw' ) {
                return (
                    index     => $idx,
                    iv        => $this_iv,
                    ct        => $ct,
                    tag       => $tag,
                    next_node => $next,
                    next_iv   => $next_iv,
                );
            }

            # ---- authenticated decrypt ------------------------------
            my $calc = substr Crypt::Digest::BLAKE2b_256::blake2b_256(
                $mac_key . $this_iv . $ct
            ), 0, MAC_OUTPUT_LEN;
            croak "MAC mismatch in node $idx" if $calc ne $tag;

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

    ###################################################################
    # Fisher–Yates shuffle – randomises traversal order
    ###################################################################

    my @perm = _deterministic_perm( Crypt::Digest::BLAKE2b_512::blake2b_512( $name . $master), scalar @closures);

    @closures      = @closures[      @perm ];
    @next_ref      = @next_ref[      @perm ];
    @next_iv_ref   = @next_iv_ref[   @perm ];
    @iv            = @iv[            @perm ];       # keep IV alignment for next_iv

    ###################################################################
    # Relink according to new order – build a Hamiltonian cycle
    ###################################################################
    for my $i ( 0 .. $#closures ) {
        my $succ = ( $i + 1 ) % @closures;          # successor index

        ${ $next_ref[$i] }    = $closures[$succ];   # set next_node
        weaken( ${ $next_ref[$i] } );               # avoid strong ref cycles
        ${ $next_iv_ref[$i] } = $iv[$succ];         # set next_iv to IV of successor
    }

    ###################################################################
    # Ring object assembly -------------------------------------------
    ###################################################################
    return (
        {
            f         => $closures[0],          # entry point is now random
            name       => $name,
            name_hash  => $name_hash_hex,
            mac_key    => $mac_key,
            aes_key    => $aes_key,
            nodes      => [ @closures ],        # keeps traversal order for debugging
        },
        undef
    );
}

1; # end of gv_c.pm

