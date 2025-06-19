package gv_c;
use v5.24;
use strict;
use warnings;

use Carp qw(croak);
use Crypt::Digest::BLAKE2b_256 qw(blake2b_256 blake2b_256_hex);
use Crypt::Digest::BLAKE2b_512 ();
use Crypt::Mode::CBC;

use constant {
    MASTER_SECRET_LEN => 32,
    MAC_KEY_LEN       => 32,
    MAC_OUTPUT_LEN    => 16,   # 128-bit tag
    AES_KEY_LEN       => 32,   # AES-256
    AES_IV_LEN        => 16,
    BLAKE_NAME_TAG    => pack('H*', 'ee4bcef77cb49c70f31de849dccaab24'),
};

#----------------------------------------------------------------------#
# Helper: minimal zeroiser (best-effort – Perl gives no hard guarantees)
#----------------------------------------------------------------------#
sub _wipe    { return unless defined $_[0]; substr($_[0], $_, 1, "\0") for 0 .. length($_[0]) - 1; $_[0] = undef }
sub _wipe_sv { _wipe(${ $_[0] }) }                 # for scalar refs

#----------------------------------------------------------------------#
# Internal mini-DSL transform used by original code
#----------------------------------------------------------------------#
my $_apply = sub {
    my ( $m, $p, $b ) = @_;
    return ( $b ^ $p )                                          if $m == 0;
    return ( ( $b << $p ) | ( $b >> ( 8 - $p ) ) ) & 0xFF       if $m == 1;
    return ( $b + $p ) & 0xFF                                   if $m == 2;
    return (~$b) & 0xFF;                                        # $m == 3
};

#----------------------------------------------------------------------#
# build_cipher_ring( name => $text, [ master_secret => $512_bytes ] )
#   → ( $ring_obj , undef | $err )
#----------------------------------------------------------------------#
sub build_cipher_ring {
    my (%a) = @_;
    my $name = $a{name} // return ( undef, 'Name required' );

    # -- master secret --------------------------------------------------
    my $master = $a{master_secret}
        ? Crypt::Digest::BLAKE2b_256::blake2b_256($a{master_secret})
        : gv_random::get_bytes(MASTER_SECRET_LEN);

    return ( undef, 'Master secret wrong length ' . length($master) )
        unless length $master == MASTER_SECRET_LEN;

    # -- static derivations ---------------------------------------------
    my $name_hash_hex = blake2b_256_hex( $name . BLAKE_NAME_TAG );
    my $mac_key       = gv_random::get_bytes(MAC_KEY_LEN);          # MAC key
    my $aes_key       = substr blake2b_256( $master . 'AES_KEY' ), 0, AES_KEY_LEN;

    # AES-CBC engine (stateless)
    my $cbc = Crypt::Mode::CBC->new( 'AES', 1 );                    # PKCS#7

    # -- node generation ------------------------------------------------
    my $iv0 = gv_random::get_bytes(AES_IV_LEN);
    my @iv  = ( $iv0 );
    my ( @ciphertext, @mac );

    my @bytes = unpack 'C*', $master;
    for my $i ( 0 .. $#bytes ) {

        # original permutation
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
        $iv[ $i + 1 ]     = substr $ct, 0, AES_IV_LEN;              # IV-chaining
    }

    # -- ring closures --------------------------------------------------
    my ( @closures, @next_ref );
    for my $idx ( 0 .. $#ciphertext ) {
        my ( $ct, $tag, $this_iv ) = ( $ciphertext[$idx], $mac[$idx], $iv[$idx] );
        my $next_iv                = $iv[ ( $idx + 1 ) % @ciphertext ];

        my $next;
        push @next_ref, \$next;

        push @closures, sub {
            my ($raw) = @_;

            # ---- raw dump used by the serializer ----------------------
            if ( defined $raw && $raw eq 'raw' ) {
                return (
                    index     => $idx,
                    iv        => $this_iv,
                    ct        => $ct,
                    tag       => $tag,
                    next_node => $next,
                );
            }

            # ---- authenticated decrypt --------------------------------
            my $calc = substr Crypt::Digest::BLAKE2b_256::blake2b_256(
                $mac_key . $this_iv . $ct
            ), 0, MAC_OUTPUT_LEN;
            croak "MAC mismatch in node $idx" if $calc ne $tag;

            my $plain = $cbc->decrypt( $ct, $aes_key, $this_iv );
            my ( $i, $stored, $mode, $param ) = unpack 'nC3', $plain;
            substr( $plain, $_, 1, "\0" ) for 0 .. length($plain) - 1;  # best-effort wipe

            return (
                index       => $i,
                stored_byte => $stored,
                mode        => $mode,
                param       => $param,
                next_node   => $next,
                next_iv     => $next_iv,
            );
        };
    }
    ${ $next_ref[$_] } = $closures[ ( $_ + 1 ) % @closures ] for 0 .. $#closures;

    # façade – now **also** exports mac_key & aes_key for secure serialisation
    return (
        {
            f => $closures[0],
            name_hash  => $name_hash_hex,
            mac_key    => $mac_key,
            aes_key    => $aes_key,
        },
        undef
    );
}

1;
