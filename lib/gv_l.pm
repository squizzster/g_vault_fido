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

        my $name_hash_hex = <$fh>;
        unless ( defined $name_hash_hex ) {
            carp "load_cipher_ring: '$filename' is empty";
            close $fh;
            return;
        }
        chomp $name_hash_hex;
        $name_hash_hex =~ s/^\s+|\s+$//g;

        if ( exists $CACHED_RING{$name_hash_hex} ) {
            close $fh;
            return $CACHED_RING{$name_hash_hex};
        }

        my $mac_key_line = <$fh>;
        my $mac_key      = q{};
        if ( defined $mac_key_line ) {
            chomp $mac_key_line;
            $mac_key_line =~ s/^\s+|\s+$//g;
            $mac_key = length $mac_key_line ? decode_base64($mac_key_line) : q{};
        }

        my ( $first_closure, $prev_next_ref );
        my %seen;
        my $nodes  = 0;
        my $lineno = 2;

        while ( my $line = <$fh> ) {
            $lineno++;
            chomp $line;
            next unless length $line;

            my $tabs = () = $line =~ /\t/g;
            if ( $tabs < 3 ) {
                carp "load_cipher_ring: malformed node at line $lineno";
                close $fh;
                return;
            }

            my ( $idx, $sb, $mode, $param ) = split /\t/, $line, 4;

            for my $f ( $idx, $sb, $mode ) {
                unless ( defined $f && length $f ) {
                    carp "load_cipher_ring: malformed node at line $lineno";
                    close $fh;
                    return;
                }
            }

            my $next;
            my $closure = sub {
                return (
                    index       => 0 + $idx,
                    stored_byte => 0 + $sb,
                    mode        => 0 + $mode,
                    param       => ( defined $param && length $param ) ? 0 + $param : undef,
                    next_node   => $next,
                );
            };

            $first_closure //= $closure;
            ${$prev_next_ref} = $closure if $prev_next_ref;
            $prev_next_ref = \$next;
            $nodes++;
        }

        close $fh;
        ${$prev_next_ref} = $first_closure if $prev_next_ref && $first_closure;

        $CACHED_RING{$name_hash_hex} = {
            first_node => $first_closure,
            mac_key    => ( length $mac_key ? $mac_key : undef ),
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
