package gv_l;
use v5.24;
use strict;
use warnings;

use Carp          qw(croak);
use MIME::Base64  qw(decode_base64);
use Scalar::Util  qw(refaddr);

# cache by 64-char Blake2-256 hex of the ring name
my %CACHED_RING;

#────────────────────────────────────────────────────────────────────
sub gv_l {
    my ($filename) = @_;

    return sub {
        local $/ = "\n";
        open my $fh, '<', $filename
            or croak "load_cipher_ring: cannot open '$filename': $!";

        # 1) first line = name-hash (hex, 64 chars)
        my $name_hash_hex = <$fh>;
        defined $name_hash_hex
            or croak "load_cipher_ring: '$filename' is empty";
        chomp $name_hash_hex;
        $name_hash_hex =~ s/^\s+|\s+$//g;

        # already cached?
        if (exists $CACHED_RING{$name_hash_hex}) {
            close $fh;
            return $CACHED_RING{$name_hash_hex};
        }

        # 2) second line = MAC key (base64)
        my $mac_key_line = <$fh>;
        defined $mac_key_line
            or croak "load_cipher_ring: '$filename' missing MAC key line";
        chomp $mac_key_line;
        my $mac_key = decode_base64($mac_key_line);

        # 3) nodes
        my ($first_closure, $prev_next_ref);
        my $nodes = 0;
        while (my $line = <$fh>) {
            chomp $line;
            next unless length $line;
            my ($idx,$sb,$mac_b64,$mode,$param) = split /\t/, $line, 5;
            my $mac = decode_base64($mac_b64);

            my $next;
            my $closure = sub {
                return (
                    index       => 0+$idx,
                    stored_byte => 0+$sb,
                    mac         => $mac,
                    mode        => $mode,
                    param       => $param,
                    next_node   => $next,
                );
            };

            $first_closure //= $closure;
            $$prev_next_ref = $closure if $prev_next_ref;
            $prev_next_ref  = \$next;
            $nodes++;
        }
        close $fh;
        $$prev_next_ref = $first_closure if $prev_next_ref && $first_closure;

        $CACHED_RING{$name_hash_hex} = {
            first_node => $first_closure,
            mac_key    => $mac_key,
            name_hash  => $name_hash_hex,
        };
        warn "[SUCCESS] Loaded [$nodes] ring elements for hash $name_hash_hex.\n";
        return $CACHED_RING{$name_hash_hex};
    };
}

sub get_cached_ring {    # accessor
    my ($hash) = @_;
    return $CACHED_RING{$hash};
}
1;
