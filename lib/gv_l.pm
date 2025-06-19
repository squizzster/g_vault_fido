# lib/gv_l.pm
#
# “PARA-MODE” Cipher-Ring Loader
# ==============================
#  • Each node is a self-contained closure.
#  • Successor links are *weak* to avoid reference cycles.
#  • The ring object keeps a strong @nodes array so closures stay
#    alive while the ring sits in %gv_l::CACHED_RING.
#  • Deleting the cache entry instantly frees everything.
#
# API
# ----
#   my $ldr  = gv_l->new;
#   $ldr->_line_in($line);      # feed each line from file/stream
#   my $ring = $ldr->_stop;     # { first_node => CODE, nodes => \@closures, name_hash => HEX }
#   my $same = gv_l::get_cached_ring($hex);
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
# Global cache: { name_hash_hex => $ring_hash }
#--------------------------------------------------------------------#
my $CACHED_RING = {};

#--------------------------------------------------------------------#
# Constructor – transient loader
#--------------------------------------------------------------------#
sub new {
    my ($class) = @_;
    return bless {
        lineno            => 0,
        nodes             => 0,
        name_hash_hex     => undef,

        mac_key           => undef,   # decoded
        aes_key           => undef,   # 32-byte decoded

        closures          => [],      # tmp array of CODE refs
        next_ref          => [],      # [ \$next_scalar, … ]
        next_iv_ref       => [],      # [ \$next_iv_scalar, … ]
        first_iv_literal  => undef,   # IV₀ to close the ring
    }, $class;
}

#--------------------------------------------------------------------#
# _line_in( $raw_line ) – feed one line
#--------------------------------------------------------------------#
sub _line_in {
    my ( $self, $line ) = @_;

    $self->{lineno}++;
    chomp $line;
    $line =~ s/^\s+|\s+$//g;

    #— header lines —#
    if    ( $self->{lineno} == 1 ) {        # name-hash
        $self->{name_hash_hex} = $line;
        if ( $CACHED_RING->{$line} ) {
            warn "CANNOT ERASE A KEY!\n";
            %$self = ();
            return;
        }
        return 1;
    }
    elsif ( $self->{lineno} == 2 ) {        # MAC key
        $self->{mac_key} = length $line ? decode_base64($line) : '';
        return 1;
    }
    elsif ( $self->{lineno} == 3 ) {        # AES key
        defined $line
          or ( carp 'load_cipher_ring: missing AES key line' ), return;
        my $aes = decode_base64($line);
        length $aes == 32
          or ( carp 'load_cipher_ring: AES key wrong length' ), return;
        $self->{aes_key} = $aes;
        return 1;
    }

    #— node lines —#
    return 1 unless length $line;

    my ( undef, $iv_b64, $ct_b64, $tag_b64 ) = split /\t/, $line, 4;
    defined $tag_b64
      or ( carp "load_cipher_ring: malformed node at line $self->{lineno}" ), return;

    my $iv  = decode_base64($iv_b64);
    my $ct  = decode_base64($ct_b64);
    my $tag = decode_base64($tag_b64);

    my $idx = $self->{nodes}++;

    # local copies only
    my $cbc     = Crypt::Mode::CBC->new('AES', 1);   # fresh XS object
    my $mac_key = $self->{mac_key};
    my $aes_key = $self->{aes_key};

    my ( $iv_l, $ct_l, $tag_l ) = ( $iv, $ct, $tag );

    # placeholders for successor info
    my ( $next, $next_iv );

    $self->{first_iv_literal} //= $iv_l;

    my $closure = sub {
        # 1) MAC check
        substr(
            Crypt::Digest::BLAKE2b_256::blake2b_256(
                $mac_key . $iv_l . $ct_l
            ), 0, 16
        ) eq $tag_l
          or do { carp "MAC mismatch in node $idx"; return };

        return do {
            # 2) decrypt header & return record
            my ( $i, $stored, $mode, $param )
              = unpack 'nC3', $cbc->decrypt( $ct_l, $aes_key, $iv_l );
            # 3) return record
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
    # store scaffolding
    push @{ $self->{closures}    }, $closure;
    push @{ $self->{next_ref}    }, \$next;
    push @{ $self->{next_iv_ref} }, \$next_iv;

    # link previous → this one
    if ( $idx > 0 ) {
        ${ $self->{next_ref}[ $idx - 1 ] } = $closure;
        weaken( ${ $self->{next_ref}[ $idx - 1 ] } );       # weak edge
        ${ $self->{next_iv_ref}[ $idx - 1 ] } = $iv_l;
    }

    return 1;
}

#--------------------------------------------------------------------#
# _stop() – finalise, wipe loader, return ring
#--------------------------------------------------------------------#
sub _stop {
    my ($self) = @_;

    unless ( $self->{nodes} ) {
        carp 'load_cipher_ring: no nodes';
        return;
    }

    # complete the ring: last → first
    ${ $self->{next_ref}[ $self->{nodes} - 1 ] } = $self->{closures}[0];
    weaken( ${ $self->{next_ref}[ $self->{nodes} - 1 ] } );
    ${ $self->{next_iv_ref}[ $self->{nodes} - 1 ] } = $self->{first_iv_literal};

    # strong @nodes array keeps closures alive while ring lives
    my @nodes = @{ $self->{closures} };

    my $ring = {
        first_node => $nodes[0],
        nodes      => \@nodes,                 # strong refs
        name_hash  => $self->{name_hash_hex},
    };
    $CACHED_RING->{ $self->{name_hash_hex} } = $ring;

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

    warn "[SUCCESS] Loaded $self->{nodes} node(s) for ring $ring->{name_hash}\n";
    return $ring;
}

#--------------------------------------------------------------------#
# Cache accessor
#--------------------------------------------------------------------#
sub get_cached_ring {
    my ($hash) = @_;
    return $CACHED_RING->{$hash};
}

1;  # end of gv_l

