# lib/gv_l.pm
#
# Hardened “cipher-ring” loader with paranoia-grade memory hygiene.
# -----------------------------------------------------------------
#  ▸ gv_l::Loader  – one-shot builder; wiped after ->stop
#  ▸ gv_l::Ring    – lightweight container; auto-scrubs on destroy
#  ▸ Global cache  – cache_ring / fetch_ring / drop_ring helpers
#
#  Typical use:
#     my $ldr  = gv_l::Loader->new;
#     $ldr->line_in($raw_line) while ... ;
#     my $ring = $ldr->stop;                 # gv_l::Ring object
#     gv_l::cache_ring($hex, $ring);         # optional
#     ...
#     my %info = $ring->f->();      # traverse
#
####################################################################

package gv_l;

use v5.24;
use strict;
use warnings;

use Carp                   qw(carp croak);
use MIME::Base64           qw(decode_base64);
use Crypt::Digest::BLAKE2b_256 qw(blake2b_256);

#------------------------------------------------------------------#
# Constants
#------------------------------------------------------------------#
use constant {
    MAC_LEN   => 16,     # 128-bit truncated BLAKE2b
    IV_LEN    => 16,     # AES block
};

#------------------------------------------------------------------#
# Global cache  { name_hash_hex ⇒ gv_l::Ring }
#------------------------------------------------------------------#
my $CR7 = {};                                   # lexical (no symbol-table)

# Public helpers ---------------------------------------------------#
sub cache_ring   { $CR7->{ $_[0] } = $_[1] }    # (id, ring)
sub fetch_ring   { $CR7->{ $_[0] } }
*get_cached_ring = \&fetch_ring;

sub drop_ring {                                # returns 1 if something was dropped
    my ($id) = @_;
    my $ring = delete $CR7->{$id} or return 0;
    $ring->__scrub;                            # free closures immediately
    return 1;
}
# Back-compat aliases
*stash_ring        = \&cache_ring;
*clear_cached_ring = \&drop_ring;

#==================================================================#
# gv_l::Loader – transient builder
#==================================================================#
package gv_l::Loader;

use strict;
use warnings;
use Carp          qw(carp croak);
use Crypt::Mode::CBC;
use Scalar::Util  qw(weaken);
use Data::Dumper  qw(Dumper);

use constant {
    MAC_LEN   => 16,     # 128-bit truncated BLAKE2b
    IV_LEN    => 16,     # AES block
};

sub new {
    my ($class) = @_;
    return bless {
        lineno    => 0,
        nodes     => 0,
        name_hash => undef,          # hex
        mac_key   => undef,          # bytes
        aes_key   => undef,          # 32 B
        closures  => [],
        next_ref  => [],
        next_iv   => [],
        first_iv  => undef,
    }, $class;
}

#------------------------------------------------------------------#
# line_in( $raw_line ) – feed one physical line
#------------------------------------------------------------------#
sub line_in {
    my ( $self, $line ) = @_;

    $self->{lineno}++;
    chomp $line;
    $line =~ s/^\s+|\s+$//g;

    # Header lines -------------------------------------------------#
    if ( $self->{lineno} == 1 ) {
        $self->{name_hash} = $line;
        gv_l::drop_ring($line);                # overwrite any old ring
        return 1;
    }
    elsif ( $self->{lineno} == 2 ) {
        $self->{mac_key} = length $line ? MIME::Base64::decode_base64($line) : '';
        return 1;
    }
    elsif ( $self->{lineno} == 3 ) {
        defined $line or croak 'load_cipher_ring: missing AES-key line';
        my $aes = MIME::Base64::decode_base64($line);
        length($aes) == 32 or croak 'load_cipher_ring: AES key wrong length';
        $self->{aes_key} = $aes;
        return 1;
    }

    # Node lines ---------------------------------------------------#
    return 1 unless length $line;              # skip blanks

    my ( undef, $iv_b64, $ct_b64, $tag_b64 ) = split /\t/, $line, 4;
    defined $tag_b64
      or croak "load_cipher_ring: malformed node at line $self->{lineno}";

    my $iv  = MIME::Base64::decode_base64($iv_b64);
    my $ct  = MIME::Base64::decode_base64($ct_b64);
    my $tag = MIME::Base64::decode_base64($tag_b64);

    # strict length checks
    length($iv)  == IV_LEN()
        or croak "IV bad";
    length($tag) == MAC_LEN()
        or croak "TAG bad";
    length($ct)  % IV_LEN() == 0
        or croak "CT bad";

    my $idx   = $self->{nodes}++;

    # Create *deep* copies of secrets (no COW)
    my $cbc   = Crypt::Mode::CBC->new('AES', 1);           # fresh XS obj
    my $mac_k = pack 'a*', $self->{mac_key};
    my $aes_k = pack 'a*', $self->{aes_key};

    my ( $iv_l, $ct_l, $tag_l ) = ( $iv, $ct, $tag );
    my ( $next,  $next_iv );                               # placeholders

    $self->{first_iv} //= $iv_l;                           # remember IV₀

    my $closure = do {
        # capture raw materials once
        my $iv_buf  = $iv_l;
        my $ct_buf  = $ct_l;
        my $tag_buf = $tag_l;
    
        # will hold the parsed node after first run
        my %memo;
        my $done = 0;
    
        sub {
            # fast path – return cached structure
            return %memo if $done;
    
            # --- 1. verify MAC --------------------------------------------------
            substr(
                Crypt::Digest::BLAKE2b_256::blake2b_256( $mac_k . $iv_buf . $ct_buf ),
                0, MAC_LEN()
            ) eq $tag_buf
              or do { carp "MAC mismatch in node $idx"; return };
    
            # --- 2. decrypt & unpack -------------------------------------------
            my ( $i, $stored, $mode, $param ) =
                unpack 'nC3', $cbc->decrypt( $ct_buf, $aes_k, $iv_buf );
    
            %memo = (
                index       => $i,
                stored_byte => $stored,
                mode        => $mode,
                param       => $param,
                next_node   => $next,
                next_iv     => $next_iv,
            );
            $done = 1;
    
            # --- 3. zeroise sensitive buffers ----------------------------------
            substr( $iv_buf,  0, length $iv_buf,  "\0" x length $iv_buf  );
            substr( $ct_buf,  0, length $ct_buf,  "\0" x length $ct_buf  );
            substr( $tag_buf, 0, length $tag_buf, "\0" x length $tag_buf );
    
            substr( $mac_k,   0, length $mac_k,   "\0" x length $mac_k   );
            substr( $aes_k,   0, length $aes_k,   "\0" x length $aes_k   );
    
            # --- 4. hand back parsed node on first call ------------------------
            return %memo;
        };
    };

    my $__closure = sub {
        # 1) MAC check
        substr( Crypt::Digest::BLAKE2b_256::blake2b_256( $mac_k . $iv_l . $ct_l ), 0, MAC_LEN() ) eq $tag_l
          or do { carp "MAC mismatch in node $idx"; return };

        # 2) decrypt & unpack  (n=16-bit idx, C3 = 3×uint8)
        my ( $i, $stored, $mode, $param )
          = unpack 'nC3', $cbc->decrypt( $ct_l, $aes_k, $iv_l );

        # 3) prepare return value
        my %node = (
            index       => $i,
            stored_byte => $stored,
            mode        => $mode,
            param       => $param,
            next_node   => $next,
            next_iv     => $next_iv,
        );

        ## --- ZEROISE sensitive buffers before exiting closure ---
        #substr( $iv_l,  0, length($iv_l),  "\0" x length($iv_l) );
        #substr( $ct_l,  0, length($ct_l),  "\0" x length($ct_l) );
        #substr( $tag_l, 0, length($tag_l), "\0" x length($tag_l) );

        # 4) return the node data
        return %node;

    };

    push @{ $self->{closures} }, $closure;
    push @{ $self->{next_ref} }, \$next;
    push @{ $self->{next_iv}  }, \$next_iv;

    if ( $idx > 0 ) {                                   # link previous → this
        ${ $self->{next_ref}[ $idx - 1 ] } = $closure;
        weaken( ${ $self->{next_ref}[ $idx - 1 ] } );   # break strong ring
        ${ $self->{next_iv}[  $idx - 1 ] } = $iv_l;
    }

    return 1;
}

#------------------------------------------------------------------#
# stop() – finalise ring, wipe loader, return gv_l::Ring
#------------------------------------------------------------------#
sub stop {
    my ($self) = @_;
    $self->{nodes} or croak 'load_cipher_ring: no nodes';

    # Close the ring (last → first)
    my $name_hash                 = "$self->{name_hash}";
    ${ $self->{next_ref}[$self->{nodes} - 1] } = $self->{closures}[0];

    weaken( ${ $self->{next_ref}[$self->{nodes} - 1] } );
    ${ $self->{next_iv}[$self->{nodes} - 1] }  = $self->{first_iv};

    gv_l::cache_ring(
        $name_hash,
        bless {
            f => $self->{closures}[0],
            nodes      => \@{ $self->{closures} },     # strong refs while cached
            name_hash  => $name_hash,
        }, 'gv_l::Ring',
    );

    warn sprintf "[SUCCESS] Loaded nodes for ring %s\n", $name_hash;
    $self->_secure_wipe;

    return 1;
}

#------------------------------------------------------------------#
# _secure_wipe – zero secrets & drop scaffolding
#------------------------------------------------------------------#
sub _secure_wipe {
    my ($self) = @_;

    for my $k ( qw/aes_key mac_key/ ) {
        next unless defined $self->{$k} && !ref $self->{$k};
        substr( $self->{$k}, 0, length $self->{$k},
                "\0" x length $self->{$k} );
        delete $self->{$k};
    }

    delete @$self{ qw/lineno nodes name_hash/ };
    delete @$self{ qw/closures next_ref next_iv first_iv/ };
}

#==================================================================#
# gv_l::Ring – lightweight container; scrubs on drop
#==================================================================#
package gv_l::Ring;

use strict;
use warnings;

### sub first_node { $_[0]->{f} }
### sub name_hash  { $_[0]->{name_hash} }

# Convenience: iterate over all closures (while still cached)
sub nodes      { @{ $_[0]->{nodes} } }

# Internal scrub – called by drop_ring & DESTROY
sub __scrub {
    my ($self) = @_;
    @{ $self->{nodes} } = ();                # release closures
    $self->{f} = undef;             # break final handle
}

sub DESTROY { shift->__scrub }

1;  # end of gv_l.pm

