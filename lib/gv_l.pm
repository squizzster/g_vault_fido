package gv_l;
use v5.24;
use strict;
use warnings;

use Carp         qw(carp);
use MIME::Base64 qw(decode_base64);
use Scalar::Util qw(refaddr);

# cache by 64-char BLAKE2b-256 hex of the ring name
my %CACHED_RING;

#────────────────────────────────────────────────────────────────────
# gv_l($filename) → coderef
#     The coderef, when called, returns the (cached) ring HASH.
#────────────────────────────────────────────────────────────────────
sub gv_l {
    my ($filename) = @_;

    return sub {
        local $/ = "\n";
        open my $fh, '<', $filename
          or carp("load_cipher_ring: cannot open '$filename': $!") and return;

        # ----- header ---------------------------------------------------
        my $name_hash_hex = <$fh>;
        chomp $name_hash_hex;
        $name_hash_hex =~ s/^\s+|\s+$//g;

        my $mac_key_line = <$fh> // '';
        chomp $mac_key_line; $mac_key_line =~ s/^\s+|\s+$//g;
        my $mac_key = length $mac_key_line ? decode_base64($mac_key_line) : q{};

        my $aes_key_line = <$fh>;
        defined $aes_key_line
            or carp "load_cipher_ring: missing AES key line" and return;
        chomp $aes_key_line; $aes_key_line =~ s/^\s+|\s+$//g;
        my $aes_key = decode_base64($aes_key_line);
        length $aes_key == 32
            or carp "load_cipher_ring: AES key wrong length" and return;

        my $cbc = Crypt::Mode::CBC->new( 'AES', 1 );                # PKCS#7

        # ----- nodes ----------------------------------------------------
        my ( @ct, @iv, @tag );
        my $lineno = 3;
        while ( my $line = <$fh> ) {
            $lineno++;
            chomp $line; next unless length $line;
            my ( $idx, $iv_b64, $ct_b64, $tag_b64 ) = split /\t/, $line, 4;
            unless ( defined $tag_b64 ) {
                carp "load_cipher_ring: malformed node at line $lineno"; return;
            }
            push @iv,  decode_base64($iv_b64);
            push @ct,  decode_base64($ct_b64);
            push @tag, decode_base64($tag_b64);
        }
        close $fh;
        my $nodes = @ct or carp "load_cipher_ring: no nodes" and return;

        # ----- build closures -------------------------------------------
        my ( @closures, @next_ref );
        for my $idx ( 0 .. $nodes - 1 ) {
            my ( $ct, $tag, $this_iv ) = ( $ct[$idx], $tag[$idx], $iv[$idx] );
            my $next_iv                 = $iv[ ( $idx + 1 ) % $nodes ];

            my $next;
            push @next_ref, \$next;

            push @closures, sub {
                my ($raw) = @_;

                return (
                    index     => $idx,
                    iv        => $this_iv,
                    ct        => $ct,
                    tag       => $tag,
                    next_node => $next,
                ) if defined $raw && $raw eq 'raw';

                my $calc = substr Crypt::Digest::BLAKE2b_256::blake2b_256(
                    $mac_key . $this_iv . $ct
                ), 0, 16;


                if ($calc ne $tag) {
                    #(we deal with this elsewhere, low-level-core library cannot crash);
                          # Return undef to signal failure without crashing. 
                    carp "CRITICAL: MAC mismatch in loaded node. Key file may be corrupt or tampered with.";
                    return;
                }

                my $plain = $cbc->decrypt( $ct, $aes_key, $this_iv );
                my ( $i, $stored, $mode, $param ) = unpack 'nC3', $plain;
                substr( $plain, $_, 1, "\0" ) for 0 .. length($plain) - 1;

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

        $CACHED_RING{$name_hash_hex} = {
            first_node => $closures[0],
            mac_key    => ( length $mac_key ? $mac_key : undef ),
            aes_key    => $aes_key,
            name_hash  => $name_hash_hex,
        };
        warn "[SUCCESS] Loaded $nodes node(s) for ring $name_hash_hex\n";
        return $CACHED_RING{$name_hash_hex};
    };
}

sub get_cached_ring {
    my ($hash) = @_;
    return $CACHED_RING{$hash};
}

1;
