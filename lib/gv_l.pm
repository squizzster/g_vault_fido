# lib/gv_l.pm
#
# PARA-MODE cipher-ring loader
# ----------------------------
#   * Each node is an independent closure (fresh CBC handle, copied keys).
#   * Successor links are weakened; a strong @nodes array in the ring
#     (stored only in the cache) keeps closures alive.
#   * _stop() wipes the loader, stores the ring in the process-wide
#     cache, prints a success message, and returns 1.
#
#   You now retrieve a ring exclusively via
#       my $ring = gv_l::get_cached_ring($hash_hex);
#
package gv_l;

use v5.24;
use strict;
use warnings;

use Carp                      qw(carp);
use MIME::Base64              qw(decode_base64);
use Crypt::Mode::CBC;
use Crypt::Digest::BLAKE2b_256;
use Scalar::Util              qw(weaken);

#--------------------------------------------------------------------#
# Global cache : { name_hash_hex → $ring_hash }
#--------------------------------------------------------------------#
my $CR7 = {};

#--------------------------------------------------------------------#
# Constructor – transient loader
#--------------------------------------------------------------------#
sub new {
    my ($class) = @_;
    return bless {
        lineno            => 0,
        nodes             => 0,
        name_hash_hex     => undef,

        mac_key           => undef,   # decoded string
        aes_key           => undef,   # 32-byte decoded string

        closures          => [],
        next_ref          => [],
        next_iv_ref       => [],
        first_iv_literal  => undef,
    }, $class;
}

#--------------------------------------------------------------------#
# _line_in( $raw_line )
#--------------------------------------------------------------------#
sub _line_in {
    my ( $self, $line ) = @_;

    $self->{lineno}++;
    chomp $line;
    $line =~ s/^\s+|\s+$//g;

    #–– header lines ––#
    if ( $self->{lineno} == 1 ) {
        $self->{name_hash_hex} = $line;
        if ( $CR7->{$line} ) {
            warn "CANNOT ERASE A KEY!\n";
            %$self = ();
            return;
        }
        return 1;
    }
    elsif ( $self->{lineno} == 2 ) {
        $self->{mac_key} = length $line ? decode_base64($line) : '';
        return 1;
    }
    elsif ( $self->{lineno} == 3 ) {
        defined $line
          or ( carp 'load_cipher_ring: missing AES key line' ), return;
        my $aes = decode_base64($line);
        length($aes) == 32
          or ( carp 'load_cipher_ring: AES key wrong length' ), return;
        $self->{aes_key} = $aes;
        return 1;
    }

    #–– node lines ––#
    return 1 unless length $line;

    my ( undef, $iv_b64, $ct_b64, $tag_b64 ) = split /\t/, $line, 4;
    defined $tag_b64
      or ( carp "load_cipher_ring: malformed node at line $self->{lineno}" ), return;

    my $iv  = decode_base64($iv_b64);
    my $ct  = decode_base64($ct_b64);
    my $tag = decode_base64($tag_b64);

    my $idx = $self->{nodes}++;

    my $cbc     = Crypt::Mode::CBC->new('AES', 1);   # fresh XS object
    my $mac_key = $self->{mac_key};                  # string copy
    my $aes_key = $self->{aes_key};                  # string copy

    my ( $iv_l, $ct_l, $tag_l ) = ( $iv, $ct, $tag );

    my ( $next, $next_iv );                          # placeholders

    $self->{first_iv_literal} //= $iv_l;

    my $closure = sub {
        substr(
            Crypt::Digest::BLAKE2b_256::blake2b_256(
                $mac_key . $iv_l . $ct_l
            ), 0, 16
        ) eq $tag_l
          or do { carp "MAC mismatch in node $idx"; return };

        return do {
             my ( $i, $stored, $mode, $param )
               = unpack 'nC3', $cbc->decrypt( $ct_l, $aes_key, $iv_l );
             (
                 index       => $i,
                 stored_byte => $stored,
                 mode        => $mode,
                 param       => $param,
                 next_node   => $next,
                 next_iv     => $next_iv,
             );
         };
    };
    push @{ $self->{closures}    }, $closure;
    push @{ $self->{next_ref}    }, \$next;
    push @{ $self->{next_iv_ref} }, \$next_iv;

    if ( $idx > 0 ) {
        ${ $self->{next_ref}[ $idx - 1 ] } = $closure;
        weaken( ${ $self->{next_ref}[ $idx - 1 ] } );
        ${ $self->{next_iv_ref}[ $idx - 1 ] } = $iv_l;
    }

    return 1;
}

#--------------------------------------------------------------------#
# _stop() – finalise, cache, wipe loader, return 1
#--------------------------------------------------------------------#
sub _stop {
    my ($self) = @_;

    unless ( $self->{nodes} ) {
        carp 'load_cipher_ring: no nodes';
        return;
    }
    my $node_count = $self->{nodes};       # save for log after wipe

    # close the ring (last → first)
    ${ $self->{next_ref}[ $node_count - 1 ] } = $self->{closures}[0];
    weaken( ${ $self->{next_ref}[ $node_count - 1 ] } );
    ${ $self->{next_iv_ref}[ $node_count - 1 ] } = $self->{first_iv_literal};

    # strong @nodes keeps closures alive while cached
    my @nodes = @{ $self->{closures} };

    my $ring = {
        first_node => $nodes[0],
        nodes      => \@nodes,
        name_hash  => $self->{name_hash_hex},
    };
    $CR7->{ "$self->{name_hash_hex}" } = $ring;

    #—— secure wipe loader ——#
    $self->{closures} = $self->{next_ref} = $self->{next_iv_ref} = [];
    delete @$self{ qw/first_iv_literal/ };

    for my $k ( qw/aes_key mac_key/ ) {
        next unless defined $self->{$k} && !ref $self->{$k};
        substr( $self->{$k}, 0, length($self->{$k}),
                "\0" x length($self->{$k}) );
        delete $self->{$k};
    }
    delete @$self{ qw/lineno nodes name_hash_hex/ };

    warn "[SUCCESS] Loaded $node_count node(s) for ring $ring->{name_hash}\n";
    return 1;
}

#--------------------------------------------------------------------#
# Cache accessor
#--------------------------------------------------------------------#
sub get_cached_ring {
    my ($hash) = @_;
    return if not defined $hash or not defined $CR7->{$hash};
    return $CR7->{$hash};
}

1;  # end of gv_l
