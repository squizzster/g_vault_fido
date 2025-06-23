############################################################################
# gv_l.pm – cipher-ring loader  rev-E3  (2025-06-23, experimental stealth)
#
#  ◇  Goals
#     • Keep ‘name’ and ‘name_hash’ public.
#     • Hide every other field/key/variable name.
#     • Minimise identifiable strings in RAM (randomised pad vars, no hints).
#  ◇  Summary of tricks
#     • Nodes array stored under a one-off random key per ring.
#     • `nodes` discovers that key lazily (memoised) — no “_k_nodes”.
#     • Each encrypted node becomes a closure built via `eval`, with
#       random pad names (lexicals) that disappear after first use.
#     • Keys/IV/tag copies wiped once validated.
############################################################################
package gv_l;

use v5.24;           # enables 'state' plus strict subs
use strict;
use warnings;

use Carp                       ();
use Crypt::Digest::BLAKE2b_256 ();
use Crypt::Misc                ();   # decode_b64()
use Scalar::Util               ();   # weaken()

########################################################################
# Constants
########################################################################
use constant {
    MAC_LEN => 16,
    IV_LEN  => 16,
};

########################################################################
# Global cache  { name_hash_hex → Ring object }
########################################################################
my $CR7 = {};

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
# Helpers – copy-on-write-safe duplication & wiping
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
use Crypt::Mode::CBC ();
use Carp ();

use constant {
    MAC_LEN        => 16,
    IV_LEN         => 16,
    BLAKE_NAME_TAG => pack('H*', 'ee4bcef77cb49c70f31de849dccaab24'),
};

#—– random 8-hex helper –––––––––––––––––––––––––––––––––––––––––––––––
sub _rnd8 { substr Crypt::Digest::BLAKE2b_256::blake2b_256_hex( rand() . $$ . time ), 0, 8 }

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
        current_blake_state => 'save_cipher_ring:',   # initial tag from gv_s.pm
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
    return $self->_fail("empty line") if !defined $line || $line eq '';

    # ── 1: Ring name ──────────────────────────────────────────────────
    if ( $self->{lineno} == 1 ) {
        $self->{name} = "$line";
        return 1;
    }
    # ── 2: Name-hash + integrity ─────────────────────────────────────
    elsif ( $self->{lineno} == 2 ) {
        my ($name_hash_from_file, $hash_from_file) = split /\t/, $line, 2;
        return $self->_fail('missing name-hash / hash on line 1')
            if !defined $name_hash_from_file || !defined $hash_from_file;

        my $exp = Crypt::Digest::BLAKE2b_256::blake2b_256_hex(
            $self->{current_blake_state} . $name_hash_from_file );

        return $self->_fail("name-hash integrity check failed")
            unless $exp eq $hash_from_file;

        return $self->_fail("name-check integrity fail") if
            $name_hash_from_file ne
            Crypt::Digest::BLAKE2b_256::blake2b_256_hex( $self->{name} . BLAKE_NAME_TAG );

        $self->{name_hash}           = $name_hash_from_file;
        $self->{current_blake_state} = $exp;

        return $self->_fail('ring already loaded') if gv_l::is_loaded_ring($self->{name_hash});
        return 1;
    }
    # ── 3: MAC key line ───────────────────────────────────────────────
    elsif ( $self->{lineno} == 3 ) {
        my ($mac_b64, $hash_from_file) = split /\t/, $line, 2;
        return $self->_fail('missing MAC key / hash on line 2')
            if !defined $mac_b64 || !defined $hash_from_file;

        my $tmp = Crypt::Misc::decode_b64($mac_b64);
        gv_l::_wipe_scalar(\$mac_b64);

        my $exp = Crypt::Digest::BLAKE2b_256::blake2b_256_hex(
            $self->{current_blake_state} . $tmp );
        return $self->_fail("MAC-key integrity check failed")
            unless $exp eq $hash_from_file;

        return $self->_fail('MAC key wrong length')
            unless length($tmp) == 2 * MAC_LEN() && $tmp ne '';

        $self->{mac_key}             = gv_l::_dup_nocow($tmp);
        gv_l::_wipe_scalar(\$tmp);
        $self->{current_blake_state} = $exp;
        return 1;
    }
    # ── 4: AES key line ───────────────────────────────────────────────
    elsif ( $self->{lineno} == 4 ) {
        my ($aes_b64, $hash_from_file) = split /\t/, $line, 2;
        return $self->_fail('missing AES key / hash on line 3')
            if !defined $aes_b64 || !defined $hash_from_file;

        my $tmp = Crypt::Misc::decode_b64($aes_b64);
        gv_l::_wipe_scalar(\$aes_b64);

        my $exp = Crypt::Digest::BLAKE2b_256::blake2b_256_hex(
            $self->{current_blake_state} . $tmp );
        return $self->_fail("AES-key integrity check failed")
            unless $exp eq $hash_from_file;

        return $self->_fail('AES key wrong length') unless length($tmp) == 32;

        $self->{aes_key}             = gv_l::_dup_nocow($tmp);
        gv_l::_wipe_scalar(\$tmp);

        $self->{current_blake_state} = $exp;
        return 1;
    }

    # ── ≥5: Encrypted nodes ───────────────────────────────────────────
    my ( undef, $iv_b64, $ct_b64, $tag_b64, $hash_int ) = split /\t/, $line, 5;
    return $self->_fail("malformed node at line $self->{lineno} (need 5 fields)")
        unless defined $hash_int;

    my $iv  = Crypt::Misc::decode_b64($iv_b64  // '');
    my $ct  = Crypt::Misc::decode_b64($ct_b64  // '');
    my $tag = Crypt::Misc::decode_b64($tag_b64 // '');

    my $exp_raw = Crypt::Digest::BLAKE2b_256::blake2b_256(
        $self->{current_blake_state} . $iv . $ct . $tag );

    return $self->_fail("node integrity check failed at line $self->{lineno}")
        unless $exp_raw eq Crypt::Misc::decode_b64($hash_int);

    $self->{current_blake_state} = $exp_raw;

    return $self->_fail('IV bad length')   unless length($iv)  == IV_LEN();
    return $self->_fail('TAG bad length')  unless length($tag) == MAC_LEN();
    return $self->_fail('CT not block-aligned') unless length($ct) % IV_LEN() == 0;

    my ($iv_l, $ct_l, $tag_l) = map { gv_l::_dup_nocow($_) } ($iv, $ct, $tag);
    gv_l::_wipe_scalar(\$_) for \$iv, \$ct, \$tag;

    my $idx = $self->{nodes}++;
    my $cbc = Crypt::Mode::CBC->new('AES', 1);

    # independent key copies
    my $mac_k = gv_l::_dup_nocow($self->{mac_key});
    my $aes_k = gv_l::_dup_nocow($self->{aes_key});

    $self->{first_iv} //= $iv_l;

    my ($next, $next_iv);
    push @{ $self->{next_ref} }, \$next;
    push @{ $self->{next_iv}  }, \$next_iv;

    # ── Build *stealth* closure – random pad names via eval –––––––––––
    my ($v_iv, $v_ct, $v_tag, $v_mac, $v_aes, $v_d, $v_e) = map { '_' . _rnd8() } 1 .. 7;

    my $closure_code = <<"EOC";
        my \$$v_iv  = \$iv_l;
        my \$$v_ct  = \$ct_l;
        my \$$v_tag = \$tag_l;
        my \$$v_mac = \$mac_k;
        my \$$v_aes = \$aes_k;
        my %$v_d;
        my \$$v_e;
        sub {
            return %$v_d if \$$v_e;
            substr(
                Crypt::Digest::BLAKE2b_256::blake2b_256(\$$v_mac.\$$v_iv.\$$v_ct),
                0, MAC_LEN()
            ) eq \$$v_tag or return;      # silent fail on MAC
            my (\$i, \$s, \$m, \$p) = unpack 'nC3',
                \$cbc->decrypt(\$$v_ct, \$$v_aes, \$$v_iv);
            %$v_d = (
                index       => \$i,
                stored_byte => \$s,
                mode        => \$m,
                param       => \$p,
                next_node   => \$next,
                next_iv     => \$next_iv,
            );
            \$$v_e = 1;
            gv_l::_wipe_scalar(\$_) for ( \\\$$v_iv, \\\$$v_ct, \\\$$v_tag, \\\$$v_mac, \\\$$v_aes );
            %$v_d;
        }
EOC

    my $closure = eval $closure_code
        or return $self->_fail("eval error in closure: $@");

    # link to previous node
    if ($idx > 0) {
        my $slot = $self->{next_ref}[$idx-1];
        $$slot   = $closure;
        Scalar::Util::weaken($$slot);
        ${ $self->{next_iv}[$idx-1] } = $iv_l;
    }

    $self->{closures}[$idx] = $closure;
    1;
}

#-----------------------------------------------------------------------
# stop – finish, seal & cache the ring
#-----------------------------------------------------------------------
sub stop {
    my ($self) = @_;
    return $self->_fail('no nodes loaded') unless $self->{nodes};

    # close the ring (last → first)
    my $tail_ref = $self->{next_ref}[ $self->{nodes} - 1 ];
    $$tail_ref   = $self->{closures}[0];
    Scalar::Util::weaken($$tail_ref);
    ${ $self->{next_iv}[ $self->{nodes} - 1 ] } = $self->{first_iv};

    # prime each closure once (zero-after-load)
    $_->() for @{ $self->{closures} };

    # ── Dynamic ring package & minimal keys ──────────────────────────
    my $rnd_key  = _rnd8();                    # random key for nodes array
    my $ring_pkg = "gv_l::" . _rnd8();         # anonymous subclass

    {
        no strict 'refs';
        @{$ring_pkg . '::ISA'} = ('gv_l::Ring');
    }

    my $ring = bless {
        f         => $self->{closures}[0],          # kept for compatibility
        $rnd_key  => [ @{ $self->{closures} } ],    # hidden nodes array
        name      => "" . $self->{name},
        name_hash => "" . $self->{name_hash},
    }, $ring_pkg;

    gv_l::cache_ring( $self->{name_hash}, $ring );
    Carp::carp sprintf '[SUCCESS] Loaded [%s] ring @%s.', $self->{name}, $ring_pkg;

    $self->_secure_wipe;
    1;
}

#-----------------------------------------------------------------------
# secure cleanup helpers
#-----------------------------------------------------------------------
sub _secure_wipe {
    my ($self) = @_;
    gv_l::_wipe_scalar(\$self->{$_}), delete $self->{$_}
        for grep defined $self->{$_}, qw/aes_key mac_key first_iv/;

    delete @$self{ qw/lineno nodes name_hash closures next_ref next_iv/ };
}

sub DESTROY { shift->_secure_wipe }

########################################################################
# gv_l::Ring – lightweight container (base class)
########################################################################
package gv_l::Ring;

use strict;
use warnings;
use Carp ();

# nodes() – find the (only) arrayref slot that isn’t name/name_hash/f
sub nodes {
    my ($self) = @_;

    # memoise per class for speed
    state %memo;
    my $class = ref $self;
    unless (exists $memo{$class}) {
        my ($k) = grep {
            $_ ne 'name'      &&
            $_ ne 'name_hash' &&
            $_ ne 'f'         &&
            ref $self->{$_} eq 'ARRAY'
        } keys %$self;
        $memo{$class} = $k // Carp::croak('nodes array not found');
    }
    return @{ $self->{ $memo{$class} } };
}

# wipe everything except name + name_hash
sub __scrub {
    my ($self) = @_;
    foreach my $k (keys %$self) {
        next if $k eq 'name' || $k eq 'name_hash';
        if (ref $self->{$k} eq 'ARRAY') {
            @{ $self->{$k} } = ();
        }
        $self->{$k} = undef;
    }
}

sub DESTROY { shift->__scrub }

1;  # end of gv_l.pm

