########################################################################
# gv_l.pm  –  2025-06-24
########################################################################
package gv_l;

use v5.14;
use strict;
use warnings;

use Carp                       ();
use Crypt::Digest::BLAKE2b_256 ();
use Crypt::Misc                ();
use Scalar::Util               ();             # no imports at top level

# ────────────────────────── top-level ring cache ──────────────────────
my %CR7;                                       # key = name-hash
=pod
     Recreating the `$CR7` Perl object ring from a raw memory dump is extraordinarily complex, costly, and high-risk.
     Perl objects internally contain absolute memory pointers valid only within their original process, making direct
     reuse impossible. The data structure involved is a sophisticated combination of hashes, tied magic layers,
     anonymous closures compiled directly into memory, and weakened references forming a circular graph. Critical
     sensitive values, such as cryptographic keys, were intentionally wiped from memory post-initialisation, further
     obscuring any reliable extraction points. Standard tools like Storable or Devel::MAT, which are typically used to
     analyse memory dumps, explicitly lack capabilities to rehydrate executable code or tied magic into a fresh Perl
     interpreter. A custom-built workflow would require detailed parsing of Perl’s internal data structures from raw
     memory, reconstructing complex relationships, re-generating closure logic from scratch, and meticulously
     recreating Perl’s tied magic system. Such an undertaking demands hundreds of engineer-hours, deep expertise in
     Perl’s internal C-level implementation, and carries an extreme risk of subtle, undetectable corruption or crashes.
=cut

# ───────────────────────────── constants ──────────────────────────────
use constant { MAC_LEN => 16, IV_LEN => 16 };

sub cache_ring     { $CR7{ $_[0] } = $_[1] }
sub fetch_ring     { my $k = shift; defined $k ? $CR7{$k} : undef }
*get_cached_ring   = \&fetch_ring;
sub is_loaded_ring { exists $CR7{ $_[0] // '' } }

sub drop_ring {
    my ($id) = @_;
    return unless $id && exists $CR7{$id};
    my $ring = delete $CR7{$id};
    $ring->__scrub;
    1;
}
*stash_ring        = \&cache_ring;
*clear_cached_ring = \&drop_ring;

# ───────────────────── copy-on-write / wiping helpers ─────────────────
sub _dup_nocow { "" . $_[0] }                  # force fresh PV
sub _wipe_scalar {
    my ($r) = @_;
    return unless defined $$r && !ref $$r;
    $$r = "" . $$r;                            # break sharing
    vec( $$r, $_, 8 ) = 0 for 0 .. length($$r) - 1;
    undef $$r;
}

########################################################################
# gv_l::Loader – builds rings from cipher-ring files
########################################################################
package gv_l::Loader;

use strict;
use warnings;
use Crypt::Mode::CBC ();
use Carp ();
use Scalar::Util qw( weaken );                 # <── import it here

use constant {
    MAC_LEN        => 16,
    IV_LEN         => 16,
    BLAKE_NAME_TAG => pack( 'H*', 'ee4bcef77cb49c70f31de849dccaab24' ),
};

# helper for anonymous package names
sub _rnd_12 { gv_hex::encode( gv_random::get_crypto_secure_prng(6) ) }

# ───────────────────────── constructor / teardown ─────────────────────
sub new {
    my ($class) = @_;
    bless {
        lineno              => 0,
        nodes               => 0,
        name                => undef,
        name_hash           => undef,
        mac_key             => undef,
        aes_key             => undef,
        closures            => [],
        next_ref            => [],
        next_iv             => [],
        first_iv            => undef,
        current_blake_state => 'save_cipher_ring:',
    }, $class;
}

sub _fail {
    my ( $self, $msg ) = @_;
    Carp::carp( $msg // 'gv_l::Loader error' );
    $self->_secure_wipe;
    return;
}

# ─────────────────────────────── line_in ──────────────────────────────
sub line_in {
    my ( $self, $line ) = @_;
    $self->{lineno}++;
    $line //= '';
    chomp $line;
    $line =~ s/^\s+|\s+$//g;

    # 1 ─ ring name
    if ( $self->{lineno} == 1 ) {
        $self->{name} = $line or return $self->_fail('empty ring name');
        return 1;
    }

    # 2 ─ name-hash + integrity
    if ( $self->{lineno} == 2 ) {
        my ( $nh, $hash ) = split /\t/, $line, 2;
        return $self->_fail('bad name-hash line') unless defined $nh && defined $hash;

        my $exp = Crypt::Digest::BLAKE2b_256::blake2b_256_hex(
            $self->{current_blake_state} . $nh
        );
        return $self->_fail('name-hash integrity fail') unless $exp eq $hash;
        return $self->_fail('ring already loaded') if gv_l::is_loaded_ring($nh);

        @{$self}{qw/name_hash current_blake_state/} = ( $nh, $exp );
        return 1;
    }

    # 3 ─ MAC key
    if ( $self->{lineno} == 3 ) {
        my ( $mac_b64, $hash ) = split /\t/, $line, 2;
        return $self->_fail('bad MAC-key line') unless defined $mac_b64 && defined $hash;

        my $mac_raw = Crypt::Misc::decode_b64($mac_b64);
        gv_l::_wipe_scalar(\$mac_b64);

        my $exp = Crypt::Digest::BLAKE2b_256::blake2b_256_hex(
            $self->{current_blake_state} . $mac_raw
        );
        return $self->_fail('MAC-key integrity fail') unless $exp eq $hash;
        return $self->_fail('MAC-key length')         unless length $mac_raw == 2 * MAC_LEN;

        $self->{mac_key}            = gv_l::_dup_nocow($mac_raw);
        gv_l::_wipe_scalar(\$mac_raw);
        $self->{current_blake_state} = $exp;
        return 1;
    }

    # 4 ─ AES key
    if ( $self->{lineno} == 4 ) {
        my ( $aes_b64, $hash ) = split /\t/, $line, 2;
        return $self->_fail('bad AES-key line') unless defined $aes_b64 && defined $hash;

        my $aes_raw = Crypt::Misc::decode_b64($aes_b64);
        gv_l::_wipe_scalar(\$aes_b64);

        my $exp = Crypt::Digest::BLAKE2b_256::blake2b_256_hex(
            $self->{current_blake_state} . $aes_raw
        );
        return $self->_fail('AES-key integrity fail') unless $exp eq $hash;
        return $self->_fail('AES-key length')         unless length $aes_raw == 32;

        $self->{aes_key}            = gv_l::_dup_nocow($aes_raw);
        gv_l::_wipe_scalar(\$aes_raw);
        $self->{current_blake_state} = $exp;
        return 1;
    }

    # ≥5 ─ encrypted node
    my ( undef, $iv_b64, $ct_b64, $tag_b64, $hash_int ) = split /\t/, $line, 5;
    return $self->_fail('malformed node line') unless defined $hash_int;

    my $iv  = Crypt::Misc::decode_b64( $iv_b64  // '' );
    my $ct  = Crypt::Misc::decode_b64( $ct_b64  // '' );
    my $tag = Crypt::Misc::decode_b64( $tag_b64 // '' );

    my $exp_raw = Crypt::Digest::BLAKE2b_256::blake2b_256(
        $self->{current_blake_state} . $iv . $ct . $tag
    );
    return $self->_fail("node integrity fail at line $self->{lineno}")
        unless $exp_raw eq Crypt::Misc::decode_b64($hash_int);

    $self->{current_blake_state} = $exp_raw;
    return $self->_fail('IV length')            unless length($iv)  == IV_LEN;
    return $self->_fail('TAG length')           unless length($tag) == MAC_LEN;
    return $self->_fail('CT not block aligned') unless length($ct)  %  IV_LEN == 0;

    # independent pad copies
    my ( $iv_l, $ct_l, $tag_l ) = map { gv_l::_dup_nocow($_) } ( $iv, $ct, $tag );
    gv_l::_wipe_scalar(\$_) for \$iv, \$ct, \$tag;

    my $idx   = $self->{nodes}++;
    my $cbc   = Crypt::Mode::CBC->new( 'AES', 1 );
    my $mac_k = gv_l::_dup_nocow( $self->{mac_key} );
    my $aes_k = gv_l::_dup_nocow( $self->{aes_key} );
    $self->{first_iv} //= $iv_l;

    my ( $next, $next_iv );                    # forward refs
    push @{ $self->{next_ref} }, \$next;
    push @{ $self->{next_iv}  }, \$next_iv;

    # ───── closure (ephemeral + compat) ─────
    my ( $v_iv,  $v_ct,  $v_tag,
         $v_mac, $v_aes ) = map { '_' . _rnd_12() } 1 .. 5;

    my $closure = eval <<"EOC" or return $self->_fail("eval error: $@");
        my \$$v_iv  = \$iv_l;
        my \$$v_ct  = \$ct_l;
        my \$$v_tag = \$tag_l;
        my \$$v_mac = \$mac_k;
        my \$$v_aes = \$aes_k;

        sub {
            return unless substr(
                Crypt::Digest::BLAKE2b_256::blake2b_256(
                    \$$v_mac . \$$v_iv . \$$v_ct
                ), 0, MAC_LEN()
            ) eq \$$v_tag;

            my (\$i, \$s, \$m, \$p) = unpack 'nC3',
                \$cbc->decrypt( \$$v_ct, \$$v_aes, \$$v_iv );

            return (
                index       => \$i,
                stored_byte => \$s,
                mode        => \$m,
                param       => \$p,
                next_node   => \$next,
                next_iv     => \$next_iv,
            ) if wantarray;

            my %d = (
                index       => \$i,
                stored_byte => \$s,
                mode        => \$m,
                param       => \$p,
                next_node   => \$next,
                next_iv     => \$next_iv,
            );
            \\%d;
        }
EOC

    # link previous node → this node
    if ( $idx > 0 ) {
        my $slot = $self->{next_ref}[ $idx - 1 ];
        $$slot   = $closure;
        weaken $$slot;                         # <── now always resolved
        ${ $self->{next_iv}[ $idx - 1 ] } = $iv_l;
    }

    $self->{closures}[$idx] = $closure;
    return 1;
}

# ─────────────────────────────── stop ────────────────────────────────
sub stop {
    my ($self) = @_;
    return $self->_fail('no nodes loaded') unless $self->{nodes};

    # close the ring (last → first)
    my $tail_ref = $self->{next_ref}[ $self->{nodes} - 1 ];
    $$tail_ref   = $self->{closures}[0];
    weaken $$tail_ref;
    ${ $self->{next_iv}[ $self->{nodes} - 1 ] } = $self->{first_iv};

    # anonymous subclass
    my $pkg = "gv_l::" . _rnd_12();
    { no strict 'refs'; @{$pkg . '::ISA'} = ('gv_l::Ring') }

    my %h;
    tie %h, 'gv_l::Ring::Tie',
        $self->{closures}[0],                 # f()
        [ @{ $self->{closures} } ],           # nodes[]
        $self->{name},                        # name
        $self->{name_hash};                   # name_hash

    gv_l::cache_ring( $self->{name_hash}, bless \%h, $pkg );
    Carp::carp sprintf '[SUCCESS] Loaded [%s] ring @%s (ephemeral-compat).',
                       $self->{name}, $pkg;

    $self->_secure_wipe;
    return 1;
}

# ───────────────────────── secure cleanup ────────────────────────────
sub _secure_wipe {
    my ($self) = @_;
    gv_l::_wipe_scalar( \$self->{$_} ), delete $self->{$_}
        for grep defined $self->{$_}, qw/ aes_key mac_key first_iv /;

    delete @$self{ qw/ lineno nodes name_hash closures next_ref next_iv / };
}
sub DESTROY { shift->_secure_wipe }

########################################################################
# gv_l::Ring::Tie – hidden storage (unchanged interface)
########################################################################
package gv_l::Ring::Tie;

use strict;
use warnings;
use Carp ();

sub TIEHASH { bless [ @_[ 1 .. 4 ] ], $_[0] }

sub FETCH {
    my ( $s, $k ) = @_;
    return $s->[0] if $k eq 'f';
    return $s->[1] if $k eq 'nodes';
    return $s->[2] if $k eq 'name';
    return $s->[3] if $k eq 'name_hash';
    undef;
}
sub STORE  { Carp::croak('gv_l::Ring is read-only') }
sub DELETE { Carp::croak('gv_l::Ring is read-only') }
sub CLEAR  { Carp::croak('gv_l::Ring is read-only') }
sub EXISTS { $_[1] =~ /^(?:f|name|name_hash|nodes)$/ }
sub FIRSTKEY { undef }
sub NEXTKEY  { undef }

sub _scrub {
    my ($s) = @_;
    $s->[0] = undef;
    @{ $s->[1] } = ();
    $s->[1] = undef;
    $_ = '' for @$s[ 2, 3 ];
}

########################################################################
# gv_l::Ring – public façade (unchanged)
########################################################################
package gv_l::Ring;

use strict;
use warnings;
use Carp ();

sub nodes {
    my ($self) = @_;
    my $tie = tied %$self or Carp::croak('ring not tied');
    @{ $tie->[1] };
}
sub f         { ( tied %{ $_[0] } )->[0] }
sub name      { ( tied %{ $_[0] } )->[2] }
sub name_hash { ( tied %{ $_[0] } )->[3] }

sub __scrub {
    my ($self) = @_;
    return unless tied %$self;
    ( tied %$self )->_scrub;
    untie %$self;
}
sub DESTROY { shift->__scrub }

1;   # end of gv_l.pm (weaken-fix)

