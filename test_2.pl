#!/usr/bin/env perl
use v5.24;
use strict;
use warnings;

# ------------------------------------------------------------
#  Library search path  (adjust if your libs live elsewhere)
# ------------------------------------------------------------
use FindBin qw($Bin);
use lib "$Bin/lib";

# ------------------------------------------------------------
#  CPAN / local deps
# ------------------------------------------------------------
use IO::Socket::UNIX;
use IO::Handle;
use Encode        qw(encode);
use Scalar::Util  qw(refaddr);

use gv_c                             ();
use gv_random;
use enter_master_password qw(get_master_key);
use Crypt::Misc                      ();
use Crypt::Digest::BLAKE2b_256
     qw(blake2b_256 blake2b_256_hex);

# ------------------------------------------------------------
#  Constants
# ------------------------------------------------------------
use constant {
    SOCKET_PATH => "\0/tmp/woofwoof.sock",   # abstract namespace
    MAX_LINE    => 4096,                     # daemon line limit
};

# ============================================================
#  1) ask for ring name
# ============================================================
print STDERR "Ring name (default = 'default'): ";
chomp( my $ring_name = <STDIN> );
$ring_name = 'default' if $ring_name eq '';

# ============================================================
#  2) derive master secret
# ============================================================
my $master_hex = get_master_key();            # interactive KDF
my $master_raw = pack('H*', $master_hex);

# ============================================================
#  3) build cipher ring
# ============================================================
my ( $ring, $err ) = gv_c::build_cipher_ring(
    name          => $ring_name,
    master_secret => $master_raw,
);
die "build_cipher_ring failed: $err\n" if $err;

# ============================================================
#  4) serialise ring exactly as gv_s::save_cipher_ring would
# ============================================================
my @lines;                                         # outbound protocol lines
push @lines, $ring->{name};

my $rolling = 'save_cipher_ring:';

$rolling = blake2b_256_hex( $rolling . $ring->{name_hash} );
push @lines, join "\t", $ring->{name_hash}, $rolling;

$rolling = blake2b_256_hex( $rolling . $ring->{mac_key} );
push @lines, join "\t", Crypt::Misc::encode_b64($ring->{mac_key}), $rolling;

$rolling = blake2b_256_hex( $rolling . $ring->{aes_key} );
push @lines, join "\t", Crypt::Misc::encode_b64($ring->{aes_key}), $rolling;

my %seen;
my $node = $ring->{f};
while ( $node && !$seen{ refaddr $node }++ ) {
    my %raw = $node->('raw');
    $rolling = blake2b_256( $rolling . $raw{iv} . $raw{ct} . $raw{tag} );

    push @lines, join "\t",
        $raw{index},
        Crypt::Misc::encode_b64( $raw{iv}  ),
        Crypt::Misc::encode_b64( $raw{ct}  ),
        Crypt::Misc::encode_b64( $raw{tag} ),
        Crypt::Misc::encode_b64( $rolling  );

    $node = $raw{next_node};
}

# ============================================================
#  5) send to daemon over UNIX socket
# ============================================================
my $sock = IO::Socket::UNIX->new(
    Type => SOCK_STREAM(),
    Peer => SOCKET_PATH,
) or die "Cannot connect to ".SOCKET_PATH.": $!\n";

$sock->autoflush(1);

print $sock "START";
print $sock "RING";

for my $line (@lines) {
    my $bytes = encode 'UTF-8', $line;
    my $len   = length $bytes;
    die "Line exceeds ".MAX_LINE." bytes – abort\n" if $len > MAX_LINE;

    print $sock pack('n', $len), $bytes;
}

print $sock pack('n', 0);   # zero-length terminator
print $sock "STOP";

# ============================================================
#  6) relay daemon replies
# ============================================================
while (1) {
    my $n = sysread $sock, my $buf, 4096;
    last unless $n;
    chomp $buf;
    print "[daemon] $buf\n";
}

exit 0;

