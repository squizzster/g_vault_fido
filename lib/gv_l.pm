package gv_l;
# gv_l.pm – (2025-06-24)
use v5.14;
use strict;
use warnings;

=pod
    The ring system is 'pure' memory obscurity.
      The ring system is about:
        - cost
        - complexity
        - time
=cut

use Carp                       ();
use Crypt::Digest::BLAKE2b_256 ();
use Crypt::Misc                ();
use Scalar::Util               ();   # I don't like any imports at top level.

# ───────────────────────────── constants ──────────────────────────────
use constant { MAC_LEN => 16, IV_LEN => 16 };

=pod
The system is secure against casual attackers and most skilled ones. 
Only a highly motivated, exceptionally skilled, and well-resourced attacker would likely succeed. 
The cost (time, expertise) of such an attack is very high.
I have supplied some useful POD documentation in this source code to make the process easier.
=cut

=pod
I utiliseed Perl, as the combination of MAGIC, flag-based weak references, arena allocation, 
makes the re-construction challenge very hard. Python’s simpler, more self-describing heap means the 
same ring would be easier especially as Python has highly mature recent memory dump analysis tools.

Of course, Perl hackers are a dying breed -- it started as a bit of fun to protect by configuration
files... however this is a full production ready version which should never crash or gain memory.

If you install it, and you are "root" hacked then you are still protected.
It is a fast, easy to use "root" hack protection system without kernel, or hardware integrations.
=cut

#======================================================================
#  ░█▀▀░█░█░█▀▄░▀█▀░█▀▀
#  ░█░░░█░█░█▀▄░░█░░▀▀█
#  ░▀▀▀░▀▀▀░▀░▀░▀▀▀░▀▀▀       (internal helpers)
#======================================================================

#----------------------------------------------------------------------
# gv_l::Cache – centralised cache with the four classic verbs
#----------------------------------------------------------------------
package gv_l::Cache;
use strict;
use warnings;
use Scalar::Util qw( weaken );

my $CACHE = {};
sub op {
    my ($verb,$k,$v)=@_;
    return exists $CACHE->{$k}            if $verb eq 'exists';
    return defined $k ? $CACHE->{$k} : undef
                                             if $verb eq 'get';
    return $CACHE->{$k} = $v              if $verb eq 'set';
    return delete $CACHE->{$k}            if $verb eq 'drop';
    die "Unknown op '$verb'";
}

#----------------------------------------------------------------------
# gv_l::SecureUtil – low-level memory sanitation
#----------------------------------------------------------------------
package gv_l::SecureUtil;
use strict; use warnings;
sub _dup_nocow { "" . $_[0] }  # AI_GOOD: force fresh PV
sub _wipe_scalar {             # AI_GOOD: zero then undef
    my ($r)=@_;
    return unless defined $$r && !ref $$r;
    $$r = "".$$r;                        # break sharing
    vec($$r,$_,8)=0 for 0..length($$r)-1;
    undef $$r;
}
# re-export for legacy callers
*gv_l::SecureUtil::_dup_nocow  = \&_dup_nocow;
*gv_l::SecureUtil::_wipe_scalar= \&_wipe_scalar;

# return to main package namespace
package gv_l;

# ────────────────── public wrappers (unchanged signatures) ────────────
sub cache_ring     { gv_l::Cache::op(set   => @_) }  # AI_GOOD
sub fetch_ring     { gv_l::Cache::op(get   => @_) }
*get_cached_ring   = \&fetch_ring;
sub is_loaded_ring { gv_l::Cache::op(exists=> @_) }
sub drop_ring      {                              # AI_CLARIFY: mirrored
    my ($id)=@_;
    return unless $id && is_loaded_ring($id);
    my $ring = gv_l::Cache::op(drop => $id);
    $ring->__scrub;
    1;
}
*stash_ring        = \&cache_ring;
*clear_cached_ring = \&drop_ring;

#======================================================================
#  ░█░█░█▀█░█▀▄░▀█▀░█▀█░█▀▀░█▀▀
#  ░█░█░█░█░█▀▄░░█░░█░█░█░█░█▀▀
#  ░▀▀▀░▀▀▀░▀░▀░▀▀▀░▀░▀░▀▀▀░▀▀▀
#       Loader – state-machine parser
#======================================================================
package gv_l::Loader;
use strict; use warnings;
use Carp ();
use Crypt::Mode::CBC ();
use Scalar::Util qw( weaken );

#----------------------------------------------------------------------
# constants local to Loader
#----------------------------------------------------------------------
use constant {
    BLAKE_NAME_TAG => pack('H*','ee4bcef77cb49c70f31de849dccaab24'),
};

#----------------------------------------------------------------------
# constructor / teardown
#----------------------------------------------------------------------
sub new {
    my ($class)=@_;
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

# generic failure helper (preserves messages verbatim)
sub _fail {
    my ($self,$msg)=@_;
    Carp::carp($msg//'gv_l::Loader error');
    $self->_secure_wipe;
    return;
}

#----------------------------------------------------------------------
# public ∙ core entry – much shorter: dispatch→handlers
#----------------------------------------------------------------------
sub line_in {
    my ($self,$line)=@_;
    $self->{lineno}++;
    $line//=q{}; chomp $line; $line=~s/^\s+|\s+$//g;

    return $self->_handle_ring_name($line)  if $self->{lineno}==1;
    return $self->_handle_name_hash($line)  if $self->{lineno}==2;
    return $self->_handle_mac_key($line)    if $self->{lineno}==3;
    return $self->_handle_aes_key($line)    if $self->{lineno}==4;
    return $self->_handle_node_line($line);                       # >=5
}

#----------------------------------------------------------------------
# 4 tiny header-line handlers
#----------------------------------------------------------------------
sub _handle_ring_name {            # line 1
    my ($self,$line)=@_;
    $self->{name}=$line or return $self->_fail('empty ring name');
    1;
}

sub _expect_blake_hex {            # helper for integrity checks
    my ($self,$inp,$exp_hex,$desc)=@_;
    my $calc = Crypt::Digest::BLAKE2b_256::blake2b_256_hex($inp);
    return 1 if $calc eq $exp_hex;
    return $self->_fail("$desc integrity fail");
}

sub _handle_name_hash {            # line 2
    my ($self,$line)=@_;
    my ($nh,$hash)=split /\t/,$line,2;
    return $self->_fail('bad name-hash line')
        unless defined $nh && defined $hash;

    $self->_expect_blake_hex(
        $self->{current_blake_state}.$nh, $hash, 'name-hash')
        or return;

    return $self->_fail('ring already loaded')
        if gv_l::is_loaded_ring($nh);

    @{$self}{qw/name_hash current_blake_state/}=($nh,$hash);
    1;
}

sub _decode_and_wipe {             # centralised B64 decode
    my ($b64)=@_;
    my $raw = Crypt::Misc::decode_b64($b64);
    gv_l::SecureUtil::_wipe_scalar(\$b64);
    $raw;
}

sub _handle_mac_key {              # line 3
    my ($self,$line)=@_;
    my ($mac_b64,$hash)=split /\t/,$line,2;
    return $self->_fail('bad MAC-key line')
        unless defined $mac_b64 && defined $hash;

    my $mac_raw=_decode_and_wipe($mac_b64);

    $self->_expect_blake_hex(
        $self->{current_blake_state}.$mac_raw,
        $hash,'MAC-key')
        or return;

    return $self->_fail('MAC-key length')
        unless length($mac_raw)==2*gv_l::MAC_LEN();

    $self->{mac_key}= gv_l::SecureUtil::_dup_nocow($mac_raw);
    gv_l::SecureUtil::_wipe_scalar(\$mac_raw);
    $self->{current_blake_state}=$hash;
    1;
}

sub _handle_aes_key {              # line 4
    my ($self,$line)=@_;
    my ($aes_b64,$hash)=split /\t/,$line,2;
    return $self->_fail('bad AES-key line')
        unless defined $aes_b64 && defined $hash;

    my $aes_raw=_decode_and_wipe($aes_b64);

    $self->_expect_blake_hex(
        $self->{current_blake_state}.$aes_raw,
        $hash,'AES-key')
        or return;

    return $self->_fail('AES-key length')
        unless length($aes_raw)==32;

    $self->{aes_key}= gv_l::SecureUtil::_dup_nocow($aes_raw);
    gv_l::SecureUtil::_wipe_scalar(\$aes_raw);
    $self->{current_blake_state}=$hash;
    1;
}

#----------------------------------------------------------------------
# Node-line handler (major logic split further for clarity)
#----------------------------------------------------------------------
sub _handle_node_line {
    my ($self,$line)=@_;

    my (undef,$iv_b64,$ct_b64,$tag_b64,$hash_int)=split /\t/,$line,5;
    return $self->_fail('malformed node line')
        unless defined $hash_int;

    # -- decode and wipe ------------------------------------------------
    my $iv  = _decode_and_wipe($iv_b64);
    my $ct  = _decode_and_wipe($ct_b64);
    my $tag = _decode_and_wipe($tag_b64);

    # -- integrity check ------------------------------------------------
    my $exp_raw = Crypt::Digest::BLAKE2b_256::blake2b_256(
        $self->{current_blake_state}.$iv.$ct.$tag);

    return $self->_fail("node integrity fail at line $self->{lineno}")
        unless $exp_raw eq Crypt::Misc::decode_b64($hash_int);

    $self->{current_blake_state}=$exp_raw;

    # -- structural sanity ---------------------------------------------
    return $self->_fail('IV length')            unless length($iv)==gv_l::IV_LEN();
    return $self->_fail('TAG length')           unless length($tag)==gv_l::MAC_LEN();
    return $self->_fail('CT not block aligned') unless length($ct)%gv_l::IV_LEN()==0;

    # -- isolated copies (Law 1: aliasing behaviour) -------------------
    my ($iv_l,$ct_l,$tag_l) = map { gv_l::SecureUtil::_dup_nocow($_) } ($iv,$ct,$tag);
    gv_l::SecureUtil::_wipe_scalar(\$iv); 
    gv_l::SecureUtil::_wipe_scalar(\$ct); 
    gv_l::SecureUtil::_wipe_scalar(\$tag);

    # -- build closure & register --------------------------------------
    $self->_register_node($iv_l,$ct_l,$tag_l);
    1;
}

sub _register_node {                               # AI_GOOD: ≤40 LOC
    my ($self,$iv_l,$ct_l,$tag_l)=@_;

    my $idx   = $self->{nodes}++;
    my $cbc   = Crypt::Mode::CBC->new('AES',1);
    my $mac_k = gv_l::SecureUtil::_dup_nocow($self->{mac_key});
    my $aes_k = gv_l::SecureUtil::_dup_nocow($self->{aes_key});
    $self->{first_iv}//=$iv_l;

    my ($next,$next_iv);
    push @{$self->{next_ref}}, \$next;
    push @{$self->{next_iv}},  \$next_iv;

    my $closure = _build_node_closure(
        $iv_l,$ct_l,$tag_l,$mac_k,$aes_k,$cbc,\$next,\$next_iv);

    # link previous node → this node
    if ($idx>0){
        my $slot=$self->{next_ref}[$idx-1];
        $$slot=$closure; weaken $$slot;
        ${ $self->{next_iv}[$idx-1] }=$iv_l;
    }

    $self->{closures}[$idx]=$closure;
}

#----------------------------------------------------------------------
# Node-closure factory (unchanged observable logic)
#----------------------------------------------------------------------

sub _build_node_closure {
    my ($iv_l,$ct_l,$tag_l,$mac_k,$aes_k,$cbc,$next_ref,$next_iv_ref)=@_;

    # Role names and mapping to incoming param variable names
    my @roles  = qw(iv ct tag mac aes);
    my @param_names = qw($iv_l $ct_l $tag_l $mac_k $aes_k);

    # Shuffle mapping for obfuscation
    my @idx = List::Util::shuffle(0..4);

    my @shuf_roles = @roles[@idx];
    my @shuf_params = @param_names[@idx];

    # Generate random lexical names for each role
    my @varnames = map { '_' . _rnd_12() } 1..5;

    # Mapping for use below: ($lexical, $param)
    my @decl_args;
    for my $i (0..4) {
        push @decl_args, $varnames[$i], $shuf_params[$i];
    }

    # Helper to get var by role in shuffled set
    my %role2var;
    @role2var{@shuf_roles} = @varnames;

    # Now assemble argument order for sprintf:
    # BLAKE2b_256( MAC, IV, CT )
    my @blake_args = @role2var{qw(mac iv ct)};
    my $tag_var    = $role2var{tag};

    # Decrypt (CT, AES, IV)
    my @decrypt_args = @role2var{qw(ct aes iv)};

    return eval sprintf <<'EOC',
    my $%s = %s;
    my $%s = %s;
    my $%s = %s;
    my $%s = %s;
    my $%s = %s;
    
    sub {
        return unless substr(
            Crypt::Digest::BLAKE2b_256::blake2b_256(
                $%s . $%s . $%s
            ), 0, gv_l::MAC_LEN()
        ) eq $%s;
    
        my ($i,$s,$m,$p) = unpack 'nC3',
            $cbc->decrypt($%s, $%s, $%s);
    
        return (
            index       => $i,
            stored_byte => $s,
            mode        => $m,
            param       => $p,
            next_node   => ${$next_ref},
            next_iv     => ${$next_iv_ref},
        ) if wantarray;
    
        my %%d = (
            index       => $i,
            stored_byte => $s,
            mode        => $m,
            param       => $p,
            next_node   => ${$next_ref},
            next_iv     => ${$next_iv_ref},
        );
        \%%d;
    }
EOC
    @decl_args, @blake_args, $tag_var, @decrypt_args;
}

# helper – random 12-hex bytes for anon package/symbols
sub _rnd_12 {
    gv_hex::encode( gv_random::get_crypto_secure_prng(6) )
}

#----------------------------------------------------------------------
# stop() – ring finalisation
#----------------------------------------------------------------------
sub stop {
    my ($self)=@_;
    return $self->_fail('no nodes loaded') unless $self->{nodes};

    $self->_link_nodes;
    $self->_finalise_ring;
    $self->_secure_wipe;
    1;
}

sub _link_nodes {
    my ($self)=@_;
    my $tail_ref = $self->{next_ref}[ $self->{nodes}-1 ];
    $$tail_ref   = $self->{closures}[0]; weaken $$tail_ref;
    ${ $self->{next_iv}[ $self->{nodes}-1 ] } = $self->{first_iv};
}

sub _finalise_ring {
    my ($self)=@_;

    my $pkg = "gv_l::" . _rnd_12();
    { no strict 'refs'; @{$pkg.'::ISA'} = ('gv_l::Ring') }

    my %h;
    tie %h, 'gv_l::Ring::Tie',
        $self->{closures}[0],
        [ @{ $self->{closures} } ],
        $self->{name},
        $self->{name_hash};

    gv_l::cache_ring($self->{name_hash}, bless \%h, $pkg);
    Carp::carp sprintf '[SUCCESS] Loaded [%s] ring @%s (ephemeral-compat).',
                       $self->{name}, $pkg;
}

#----------------------------------------------------------------------
# secure cleanup
#----------------------------------------------------------------------
sub _secure_wipe {
    my ($self)=@_;
    gv_l::SecureUtil::_wipe_scalar(\$self->{$_}), delete $self->{$_}
        for grep defined $self->{$_}, qw/aes_key mac_key first_iv/;
    delete @$self{qw/lineno nodes name_hash closures next_ref next_iv name/};
}
sub DESTROY { shift->_secure_wipe }

#======================================================================
#  ░█▀▀░█▀█░█▄█░█▀▄
#  ░█░█░█░█░█░█░█▀▄
#  ░▀▀▀░▀▀▀░▀░▀░▀░▀     Tie object – cleaner FETCH
#======================================================================
package gv_l::Ring::Tie;
use strict; use warnings;
use Carp ();

sub TIEHASH { bless [ @_[1..4] ], $_[0] }  # [f,nodes,name,name_hash]

my %FIELDS = ( f=>0, nodes=>1, name=>2, name_hash=>3 );
sub FETCH   { $_[0]->[ $FIELDS{ $_[1] } // return undef ] }

# read-only guard
sub _ro { Carp::croak('gv_l::Ring is read-only') }
*STORE  = *_ro; *DELETE = *_ro; *CLEAR = *_ro;
sub EXISTS { exists $FIELDS{ $_[1] } }
sub FIRSTKEY { undef } sub NEXTKEY { undef }

sub _scrub {
    my ($s)=@_;
    $s->[0]=undef; @{ $s->[1] }=(); $s->[1]=undef;
    $_='' for @$s[2,3];
}

#======================================================================
#  ░█▀▀░█▀█░█▀█░█▀▀░█▀▀
#  ░█▀▀░█░█░█░█░█░█░█▀▀
#  ░▀░░░▀▀▀░▀░▀░▀▀▀░▀▀▀    Facade methods
#======================================================================
package gv_l::Ring;
use strict; use warnings; use Carp ();

sub _tie { tied %{ $_[0] } or Carp::croak('ring not tied') }

sub nodes      { my $t=_tie($_[0]); @{ $t->[1] } }
sub f          { _tie($_[0])->[0] }
sub name       { _tie($_[0])->[2] }
sub name_hash  { _tie($_[0])->[3] }


sub __scrub {
    my ($self) = @_;
    return unless tied %$self;
    ( tied %$self )->_scrub;
    untie %$self;
}

sub DESTROY { shift->__scrub }

1;  # end of gv_l.pm refactor

=pod
  Reconstructing a `gv_l::Ring` Perl instance from only a raw or core-format memory dump, combined with a
  fully stripped Perl binary compiled without debug symbols, is an exceptionally challenging task, demanding
  an elite combination of memory-forensics skill, reverse-engineering experience, and deep, internal Perl
  interpreter knowledge. This difficulty arises from multiple sophisticated technical obstacles embedded
  within Perl’s memory architecture.
  
  The fundamental issue starts with the memory dump itself: all pointers stored in Perl data structures—
  scalars (SVs), hashes (HVs), arrays (AVs), and code closures (CVs)—reference virtual addresses valid solely
  within the original runtime process space. Due to Address Space Layout Randomisation (ASLR), including
  position-independent executable (PIE) segments and heap randomisation, these pointers must be meticulously
  rebased before they hold any forensic meaning, making naive pointer-following infeasible.
  
  Compounding this is the absence of symbol data, as the Perl binary has been stripped, removing critical
  debugging symbols and DWARF metadata. Standard debugging tools such as GDB, radare2, or Pwndbg thus lose
  their immediate capability to auto-apply Perl-specific pretty-printers. Analysts must first precisely
  recreate a matching Perl debug build—identical in revision, compile-time configuration, and compiler
  flags—and then manually re-import its debug symbols into their forensic tools, a demanding preparatory step
  essential to even basic analysis.
  
  Another major complexity lies within Perl’s internal memory allocator: scalars, arrays, and hashes exist
  within dynamically managed arenas, whose allocations and deallocations produce significant memory churn.
  
  Moreover, Perl's internal use of weak references, marked by the `SvWEAKREF` flag, profoundly complicates
  the process of reconstructing logical object graphs. The ring’s internal linking uses exclusively weak
  references, making these closure references invisible to standard graph traversal methods. Analysts must
  explicitly and manually handle these flags to reconstruct accurate relationships. Additionally, each
  closure’s reference to its outer lexical context is weak (`CvWEAKOUTSIDE`), further obscuring direct
  traversal paths.
  
  The top-level hash structure of the `gv_l::Ring` itself uses Perl’s MAGIC system (`PERL_MAGIC_tied`),
  embedding keys and data behind opaque pointers (`mg_ptr`) that require explicit internal Perl hash-walking
  techniques at the C-level. Identifying and interpreting tied hashes demands intricate understanding of
  Perl’s internal representation of MAGIC, posing a significant barrier for anyone not deeply versed in Perl
  internals.
  
  Adding another cryptographic dimension, each node in the ring includes duplicated block-cipher payloads—
  Initialization Vectors (IVs), ciphertexts (CT), and authentication tags (TAG)—which are memory-aligned,
  randomised byte sequences designed to evade simple pattern matching. The eval-based obfuscation layer in
  the closure pads, randomising lexical variable names, although superficially challenging, is realistically
  overcome through heuristic length-based inspection of the stored scalar payloads rather than direct lexical
  analysis.
  
  In summary, reconstructing a `gv_l::Ring` object—including extraction of embedded cryptographic keys—from a
  stripped Perl binary and raw memory dump is technically plausible but exceedingly complex. It necessitates
  advanced tooling, expert-level forensic skill, comprehensive Perl interpreter knowledge, and considerable
  manual reverse-engineering effort. The intricate interplay of ASLR, weak references, allocator-induced
  noise, tied MAGIC indirections, cryptographic payload randomisation, and symbol-stripped binaries creates
  formidable forensic hurdles. No single security measure within the ring construction guarantees absolute
  protection; rather, the cumulative layering of sophisticated internal Perl features significantly elevates
  attacker cost, complexity, and time, placing full reconstruction realistically within reach only for expert
  teams with substantial forensic resources and specialised technical expertise.
=cut

=pod
1. TIED HASH WRAPPER:
HV (blessed into random pkg that ISA gv_l::Ring)
│  FLAGS  = SVt_PVHV | SVf_POK | ...
│  MAGIC  = PERL_MAGIC_tied (‘P’)
│  mg_ptr = mg_obj  ──►  AV  (the gv_l::Ring::Tie array)
│  Keys:  ‘f’, ‘nodes’, ‘name’, ‘name_hash’
│         → ordinary HE* entries, each storing an SV


2. ANSI diagram of one node in context:
                ┌──────────────────────────────────────────────────────────┐
                │  @closures  (AV)                                         │
                │  • ...                                                   │
                │  • [idx] = CV* ─────────────────┐                        │
                └─────────────────────────────────┘                        │
                                           strong ref                      │
                                           (array element)                 │
                                           │                               │
┌──────────────────────────────────────────────────────────────────────────▼─┐
│ CV (node-closure)                                                         │
│ ├─ REFCOUNT = 1  (+ temps)                                                │
│ ├─ FLAGS  = CVf_CLONE | CVf_WEAKOUTSIDE | CVf_ANON | …                    │
│ ├─ CvPADLIST → AV                                                         │
│ │   ┌─[0] PVMG (SV* to $cbc object)                                       │
│ │   ├─[1] PV   $iv_l                                                      │
│ │   ├─[2] PV   $ct_l                                                      │
│ │   ├─[3] PV   $tag_l                                                     │
│ │   ├─[4] RV   (WEAK) ───────────────► next CV (idx+1 mod N)              │
│ │   └─[5] RV   → scalar holding next_iv string                            │
│ ├─ CvOUTSIDE (WEAK) → builder CV                                          │
│ └─ CvROOT / op-tree                                                       │
└───────────────────────────────────────────────────────────────────────────┘


3. And wrapping that:
 HV (gv_l::Ring hash)          mg_obj                gv_l::Cache (global)
┌────────────────────┐    ┌───────────────┐     ┌────────────────────────┐
│ keys: f nodes ...  │──► │ AV = tie obj  │     │  { name_hash ⇒ HV }    │
│ MAGIC ‘P’          │    └───────────────┘     └────────────────────────┘
└────────────────────┘
=cut
