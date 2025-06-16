package g_checksum;

use strict;
use warnings;
use utf8;

use Scalar::Util qw(refaddr blessed reftype);
use Encode        qw(encode_utf8);
use Crypt::Digest::BLAKE2b_256 qw(
    blake2b_256
    blake2b_256_hex
);

# ----------------------------------------------------------------------
# checksum_data_v2(@items)
#
# * Each top-level item is canonically serialised (see _canonical_data).
# * We hash that canonical string with BLAKE2b-256 (raw, 32 bytes).
# * We concatenate all those 32-byte blocks and hash the whole blob
#   once more, yielding a single, fixed-length hex digest.
# ----------------------------------------------------------------------

sub checksum_data_v2 {
    my @items = @_;

    my $final_raw = '';          # concatenation of partial digests

    my $state = {                # shared state for recursion
        cache      => {},        # addr → canonical string
        inprogress => {},        # addr → 1   (cycle detection)
        refid      => {},        # addr → stable integer ID
        next_id    => 1,
    };

    for my $item (@items) {
        my $canon = _canonical_data($item, $state);
        $final_raw .= blake2b_256($canon);
    }

    return blake2b_256_hex($final_raw);
}

# ----------------------------------------------------------------------
# _canonical_scalar($str) → canonical string for a *defined* scalar
#   - Always encoded as UTF-8 octets.
#   - Prefix is the *byte* length, so the format is self-consistent.
# ----------------------------------------------------------------------

sub _canonical_scalar {
    my ($str) = @_;
    my $bytes = encode_utf8($str);              # raw octets
    return 'S' . length($bytes) . ':' . $bytes; # e.g. S3:foo
}

# ----------------------------------------------------------------------
# _canonical_data($data, $state) → canonical string
#
#  * UNDEF scalar              → "U"
#  * Defined scalar            → "S<bytes>:<utf8-octets>"
#  * Array ref                 → "R<id>:A[elem1,elem2,…]"
#  * Hash  ref                 → "R<id>:H{k1=>v1,k2=>v2,…}" (keys sorted)
#  * Scalar ref                → "R<id>:SR<value>"
#  * Circular ref placeholder  → "R<id>:C"
#  * Blessed ref / other types → "U"      (treated as undefined, per spec)
#
#  Stable IDs (R<id>) ensure repeated references hash identically,
#  while cycle detection (“inprogress”) prevents infinite recursion.
# ----------------------------------------------------------------------

sub _canonical_data {
    my ($data, $state) = @_;

    # 1) Undefined scalar
    return 'U' unless defined $data;

    # 2) Plain scalar
    unless (ref $data) {
        return _canonical_scalar($data);
    }

    # 3) Unsupported: blessed reference → treat as undefined (“U”)
    return 'U' if blessed($data);

    # From here on we know it is an unblessed reference -----------------
    my $addr = refaddr($data);

    # Already serialised?
    return $state->{cache}{$addr} if exists $state->{cache}{$addr};

    # Cycle?
    if ($state->{inprogress}{$addr}) {
        $state->{refid}{$addr} //= $state->{next_id}++;
        my $cid = $state->{refid}{$addr};
        return "R${cid}:C";
    }

    # First time we see this reference
    $state->{inprogress}{$addr} = 1;
    $state->{refid}{$addr} //= $state->{next_id}++;
    my $id     = $state->{refid}{$addr};
    my $rtype  = reftype($data) // '';   # SCALAR, ARRAY, HASH, REF, …

    my $result;

    if ($rtype eq 'HASH') {
        # Keys in *sorted* order for determinism
        my @pairs;
        for my $k (sort keys %$data) {
            my $kcanon = _canonical_scalar($k);        # key is always scalar
            my $vcanon = _canonical_data($data->{$k}, $state);
            push @pairs, "$kcanon=>$vcanon";
        }
        $result = "R${id}:H\{" . join(',', @pairs) . "\}";
    }
    elsif ($rtype eq 'ARRAY') {
        my @elems = map { _canonical_data($_, $state) } @$data;
        $result = "R${id}:A\[" . join(',', @elems) . "\]";
    }
    elsif ($rtype eq 'SCALAR' || $rtype eq 'REF') {         # scalar ref
        my $inner = _canonical_data($$data, $state);
        $result = "R${id}:SR<${inner}>";
    }
    else {
        # Everything else (GLOB, CODE, REGEXP, etc.) → treat as undef
        $result = 'U';
    }

    # Cache & unwind
    delete $state->{inprogress}{$addr};
    $state->{cache}{$addr} = $result;

    return $result;
}

1;  # end of g_checksum

