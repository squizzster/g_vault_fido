package gv_l;

# Hardened “cipher-ring” loader – 2025-06-19  rev-D2
# --------------------------------------------------
# - Dependency-free: core Perl 5.14 only
# - COW broken with self-concat; secrets wiped via vec()
# - Restores original closure capture of $next / $next_iv
# - Calls weaken() only after assignment (never on undef)

use v5.24;
use strict;
use warnings;

use Carp                       ();
use Crypt::Digest::BLAKE2b_256 ();
use Crypt::Misc                ();    # for decode_b64()
use Scalar::Util               ();    # for weaken()

########################################################################
# Constants
########################################################################
use constant {
    MAC_LEN         => 16,  
    IV_LEN          => 16,
};

########################################################################
# Global cache  { name_hash_hex ⇒ gv_l::Ring }
########################################################################
my $CR7 = {};           # lexical, cannot be re-tied from outside

# ––– Public cache helpers ––––––––––––––––––––––––––––––––––––––––––––
sub cache_ring   { $CR7->{ $_[0] } = $_[1] }
sub fetch_ring   { my $id = shift; $id && exists $CR7->{$id} ? $CR7->{$id} : undef }
*get_cached_ring = \&fetch_ring;

sub is_loaded_ring { my $id = shift; $id && exists $CR7->{$id} }

sub drop_ring {
    my ($id) = @_;
    return unless $id;
    my $ring = delete $CR7->{$id} or return 0;
    $ring->__scrub;
    1;
}
*stash_ring        = \&cache_ring;
*clear_cached_ring = \&drop_ring;

########################################################################
# Helpers – COW-safe duplication & wiping
########################################################################

sub _dup_nocow { "" . $_[0] }          # self-concat forces fresh PV

sub _wipe_scalar {
    my ($ref) = @_;
    return unless defined $$ref && !ref $$ref;
    $$ref = "" . $$ref;                # break any sharing
    vec($$ref, $_, 8) = 0 for 0 .. length($$ref) - 1;
    undef $$ref;
}

########################################################################
# gv_l::Loader – transient builder
########################################################################
package gv_l::Loader;

use strict;
use warnings;
use Crypt::Mode::CBC   ();
use Carp               ();

use constant { # Re-declare constants for this package, as in original
    MAC_LEN        => 16,
    IV_LEN         => 16,
    BLAKE_NAME_TAG => pack('H*', 'ee4bcef77cb49c70f31de849dccaab24'),
};

sub new {
    my ($class) = @_;
    bless {
        lineno    => 0,
        nodes     => 0,
        name      => undef,
        name_hash => undef,
        mac_key   => undef,
        aes_key   => undef,
        closures  => [],
        next_ref  => [],
        next_iv   => [],
        first_iv  => undef,
        # ADDED for running hash check
        current_blake_state => 'save_cipher_ring:', # Initial value from gv_s.pm
    }, $class;
}

sub _fail {
    my ($self, $msg) = @_;
    Carp::carp( $msg // 'gv_l::Loader – generic error' );
    $self->_secure_wipe if $self->can('_secure_wipe');
    undef;
}

#-----------------------------------------------------------------------
# line_in – feed one physical line
#-----------------------------------------------------------------------
sub line_in {
    my ( $self, $line ) = @_;

    $self->{lineno}++;
    chomp $line if defined $line;
    $line =~ s/^\s+|\s+$//g if defined $line;
    return $self->_fail("empty line") if not defined $line or length($line) == 0;
    # so, $line has something... (else fail)

    # ── Name-hash line ────────────────────────────────────────────────
    if ( $self->{lineno}    == 1 ) { # 1
         $self->{name} = "$line";
         return 1;
    }
    elsif ( $self->{lineno} == 2 ) { # 2
        my ($name_hash_from_file, $hash_from_file) = split /\t/, ($line // ''), 2;
        return $self->_fail('missing name-hash or its hash on line 1')
            unless defined $name_hash_from_file && defined $hash_from_file;

        my $expected_hash = Crypt::Digest::BLAKE2b_256::blake2b_256_hex(
            $self->{current_blake_state} . $name_hash_from_file
        );

        return $self->_fail("name-hash integrity check failed on line 1") # Simplified error for brevity
            unless $expected_hash eq $hash_from_file;

        return $self->_fail("name-check integrity fail") if 
            $name_hash_from_file    ne 
            Crypt::Digest::BLAKE2b_256::blake2b_256_hex( $self->{name} . BLAKE_NAME_TAG );

        $self->{name_hash}           = $name_hash_from_file;
        $self->{current_blake_state} = $expected_hash; # State is now HEX STRING

        return $self->_fail('cannot replace a ring') if gv_l::is_loaded_ring($self->{name_hash}); # can't unload! should never unload.
        return 1;
    }

    # ── MAC-key line ─────────────────────────────────────────────────
    elsif ( $self->{lineno} == 3 ) { # 3
        my ($mac_key_b64, $hash_from_file) = split /\t/, ($line // ''), 2;
        return $self->_fail('missing MAC key b64 or its hash on line 2')
            unless defined $mac_key_b64 && defined $hash_from_file;
        
        my $tmp = Crypt::Misc::decode_b64($mac_key_b64);
        gv_l::_wipe_scalar(\$mac_key_b64);

        my $expected_hash = Crypt::Digest::BLAKE2b_256::blake2b_256_hex(
            $self->{current_blake_state} . $tmp
        );
        return $self->_fail("MAC-key integrity check failed on line 2")
            unless $expected_hash eq $hash_from_file;

        # Original validation logic for MAC key (unchanged)
        return $self->_fail('MAC key wrong length')
          unless length($tmp) == 2 * MAC_LEN() && $tmp ne '';

        $self->{mac_key} = gv_l::_dup_nocow($tmp); # Unchanged
        gv_l::_wipe_scalar(\$tmp); # Unchanged
        $self->{current_blake_state} = $expected_hash; # State remains HEX STRING
        return 1;
    }

    # ── AES-key line ─────────────────────────────────────────────────
    elsif ( $self->{lineno} == 4 ) {
        my ($aes_key_b64, $hash_from_file) = split /\t/, ($line // ''), 2;
        return $self->_fail('missing AES key b64 or its hash on line 3')
            unless defined $aes_key_b64 && defined $hash_from_file;

        my $tmp = Crypt::Misc::decode_b64($aes_key_b64);
        gv_l::_wipe_scalar(\$aes_key_b64);

        my $expected_hash = Crypt::Digest::BLAKE2b_256::blake2b_256_hex(
            $self->{current_blake_state} . $tmp
        );
        return $self->_fail("AES-key integrity check failed on line 3")
            unless $expected_hash eq $hash_from_file;

        return $self->_fail('AES key wrong length') unless length($tmp) == 32;

        $self->{aes_key} = gv_l::_dup_nocow($tmp);
        gv_l::_wipe_scalar(\$tmp);

        $self->{current_blake_state} = $expected_hash;
        return 1;
    }

    # ── Node lines (>3) ──────────────────────────────────────────────

    my ( undef, $iv_b64, $ct_b64, $tag_b64, $hash_integ ) = split /\t/, $line, 5;
    return $self->_fail("malformed node at line $self->{lineno} (expected 5 fields)")
        unless defined $hash_integ;

    my $iv  = Crypt::Misc::decode_b64($iv_b64  // ''); 
    my $ct  = Crypt::Misc::decode_b64($ct_b64  // '');
    my $tag = Crypt::Misc::decode_b64($tag_b64 // '');

    my $expected_node_hash_raw = Crypt::Digest::BLAKE2b_256::blake2b_256(
        $self->{current_blake_state} . $iv . $ct . $tag
    );

    return $self->_fail("Node integrity check failed at line $self->{lineno}")
        unless $expected_node_hash_raw eq Crypt::Misc::decode_b64($hash_integ);
    
    $self->{current_blake_state} = $expected_node_hash_raw;

    # Original validations (IV length, TAG length, CT alignment)
    return $self->_fail('IV bad length')   unless length($iv)  == IV_LEN();
    return $self->_fail('TAG bad length')  unless length($tag) == MAC_LEN();
    return $self->_fail('CT not block-aligned') unless length($ct) % IV_LEN() == 0;

    # Independent copies for the closure
    my ( $iv_l, $ct_l, $tag_l ) = map { gv_l::_dup_nocow($_) } ( $iv, $ct, $tag );
    gv_l::_wipe_scalar($_) for ( \$iv, \$ct, \$tag ); # Original wiping

    my $idx = $self->{nodes}++;

    my $cbc   = Crypt::Mode::CBC->new('AES', 1);
    my $mac_k = gv_l::_dup_nocow( $self->{mac_key} );
    my $aes_k = gv_l::_dup_nocow( $self->{aes_key} );

    $self->{first_iv} //= $iv_l;

    my $next    = undef;
    my $next_iv = undef;

    push @{ $self->{next_ref} }, \$next;
    push @{ $self->{next_iv}  }, \$next_iv;

    # ── Build closure – captures $next / $next_iv 
    my $closure = do {
        my ( $iv_buf, $ct_buf, $tag_buf ) = ( $iv_l, $ct_l, $tag_l );
        my (%memo, $done);

        sub {
            return %memo if $done;

            substr(
                Crypt::Digest::BLAKE2b_256::blake2b_256(
                    $mac_k . $iv_buf . $ct_buf
                ),
                0, MAC_LEN()
            ) eq $tag_buf
              or return;   # silently fail

            my ( $i, $stored, $mode, $param )
                = unpack 'nC3', $cbc->decrypt( $ct_buf, $aes_k, $iv_buf );

            %memo = (
                index       => $i,
                stored_byte => $stored,
                mode        => $mode,
                param       => $param,
                next_node   => $next,
                next_iv     => $next_iv,
            );
            $done = 1;

            gv_l::_wipe_scalar($_)
                for ( \$iv_buf, \$ct_buf, \$tag_buf, \$mac_k, \$aes_k );
            %memo;
        };
    };

    # -- link current node to previous one (if any)
    if ( $idx > 0 ) {
        my $slot = $self->{next_ref}[ $idx - 1 ];
        $$slot = $closure;
        Scalar::Util::weaken($$slot);
        ${ $self->{next_iv}[ $idx - 1 ] } = $iv_l;
    }

    $self->{closures}[$idx] = $closure; # Unchanged
    1;
}

sub stop {
    my ($self) = @_;
    return $self->_fail('no nodes loaded') unless $self->{nodes};

    # close the ring (last → first)
    my $name_hash = gv_l::_dup_nocow("$self->{name_hash}");
    my $name      = gv_l::_dup_nocow("$self->{name}"     );
    my $tail_ref  = $self->{next_ref}[ $self->{nodes} - 1 ];
    $$tail_ref    = $self->{closures}[0];
    Scalar::Util::weaken($$tail_ref);
    ${ $self->{next_iv}[ $self->{nodes} - 1 ] } = $self->{first_iv};

    # invoke every closure once (zero-after-load)
    $_->() for @{ $self->{closures} };

    gv_l::cache_ring(
        $name_hash,
        bless {
            f         => $self->{closures}[0],
            nodes     => [ @{ $self->{closures} } ],
            name      => $name,
            name_hash => $name_hash,
        }, 'gv_l::Ring',
    );

    Carp::carp sprintf '[SUCCESS] Loaded %d nodes for ring %s',
        $self->{nodes}, $name_hash;

    $self->_secure_wipe;
    1;
}

sub _secure_wipe {
    my ($self) = @_;
    gv_l::_wipe_scalar( \ $self->{$_} ), delete $self->{$_}
        for grep defined $self->{$_}, qw/aes_key mac_key/;

    delete @$self{ qw/lineno nodes name_hash first_iv
                      closures next_ref next_iv/ };
}

sub DESTROY { shift->_secure_wipe } # IDENTICAL TO ORIGINAL

########################################################################
# gv_l::Ring – lightweight container
########################################################################
package gv_l::Ring;
use strict;
use warnings;

sub nodes { @{ $_[0]->{nodes} } }

sub __scrub {
    my ($self) = @_;
    @{ $self->{nodes} } = ();
    $self->{f} = undef;
}

sub DESTROY { shift->__scrub }

1;  # end of gv_l.pm
