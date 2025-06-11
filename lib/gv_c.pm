package gv_c;
use v5.24;
use strict;
use warnings;

use Carp           qw(croak);
use Crypt::PRNG    qw(random_bytes);
BEGIN { require Digest::BLAKE2; Digest::BLAKE2->import('blake2b') }

use constant {
    MASTER_SECRET_LEN => 512,
    MAC_KEY_LEN       => 32,
    MAC_OUTPUT_LEN    => 16,
};

# helpers
my $_apply = sub { my ($m,$p,$b)=@_;
    return ($b ^ $p)                      if $m==0;
    return (($b<<$p)|($b>>(8-$p))) & 0xFF if $m==1;
    return ($b + $p) & 0xFF               if $m==2;
    return (~$b) & 0xFF;
};
my $_mac = sub {
    my ($k,$ob,$i)=@_;
    substr blake2b("CryptoRingNodeMAC$k".pack('CN',$ob,$i)),0,MAC_OUTPUT_LEN;
};

#────────────────────────────────────────────────────────────────────
# build_cipher_ring( name => $text, [ master_secret => $512b ] )
#     → ( $ring_obj , undef | $err )
#────────────────────────────────────────────────────────────────────
sub build_cipher_ring {
    my (%a) = @_;
    my $name         = $a{name}
        // return (undef, 'Name required');
    my $master_input = $a{master_secret};

    my $master = defined $master_input
        ? $master_input
        : random_bytes(MASTER_SECRET_LEN);
    return (undef, 'Master secret wrong length')
        unless length($master) == MASTER_SECRET_LEN;

    my $name_hash_hex = unpack 'H*', substr( blake2b($name), 0, 32 );
    my $mac_key       = random_bytes(MAC_KEY_LEN);

    my @bytes = unpack 'C*', $master;
    my (@closures,@next_ref);
    for my $i (0..$#bytes) {
        my $seed = blake2b($master.pack('N',$i),'',2);
        my ($mr,$pr)=unpack 'CC',$seed;
        my $mode  = $mr % 4;
        my $param = $mode==1 ? 1+($pr%7) : $pr;
        $param    = 0 if $mode==3;

        my $stored = $_apply->($mode,$param,$bytes[$i]);
        my $mac    = $_mac->($mac_key,$bytes[$i],$i);

        my $next;
        push @next_ref, \$next;
        push @closures, sub {
            return (
                index       => $i,
                stored_byte => $stored,
                mac         => $mac,
                mode        => $mode,
                param       => $param,
                next_node   => $next,
            );
        };
    }
    ${ $next_ref[$_] } = $closures[($_+1)%@closures] for 0..$#closures;

    return ({
        first_node => $closures[0],
        mac_key    => $mac_key,
        name_hash  => $name_hash_hex,
    }, undef);
}
1;

