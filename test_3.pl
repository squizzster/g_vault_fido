#!/usr/bin/env perl
use v5.24;
use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin/lib";

use IO::Socket::UNIX;
use IO::Handle;
use Encode        qw(encode);
use Scalar::Util  qw(refaddr);

use gv_c                             ();
use enter_master_password qw(get_master_key);
use Crypt::Misc                      ();
use Crypt::Digest::BLAKE2b_256
     qw(blake2b_256 blake2b_256_hex);

use gv_random;
use constant {
    SOCKET_PATH => "\0/tmp/woofwoof.sock",
    MAX_LINE    => 4096,
};

my $ra_ra_sock = IO::Socket::UNIX->new(
    Type => SOCK_STREAM(),
    Peer => SOCKET_PATH,
) or die "Cannot connect to ".SOCKET_PATH.": $!\n";

my ($ring_name, $master_hex) = get_master_key();


my $sock = IO::Socket::UNIX->new(
    Type => SOCK_STREAM(),
    Peer => SOCKET_PATH,
) or die "Cannot connect to ".SOCKET_PATH.": $!\n";

$sock->autoflush(1);

my ( $ring, $err ) = gv_c::build_cipher_ring(
    name          => $ring_name,
    master_secret => pack('H*', $master_hex),
);
die "build_cipher_ring failed: $err\n" if $err;
print $sock "START";
print $sock "RING";

# --- Streaming lines one at a time, as produced ---
my $rolling = 'save_cipher_ring:';

# 1. name
_sendline($sock, $ring->{name});

# 2. name_hash + blake
$rolling = blake2b_256_hex( $rolling . $ring->{name_hash} );
_sendline($sock, join "\t", $ring->{name_hash}, $rolling);

# 3. MAC key + blake
$rolling = blake2b_256_hex( $rolling . $ring->{mac_key} );
_sendline($sock, join "\t", Crypt::Misc::encode_b64($ring->{mac_key}), $rolling);

# 4. AES key + blake
$rolling = blake2b_256_hex( $rolling . $ring->{aes_key} );
_sendline($sock, join "\t", Crypt::Misc::encode_b64($ring->{aes_key}), $rolling);

# 5. All nodes, streaming
my %seen;
my $node = $ring->{f};
while ( $node && !$seen{ refaddr $node }++ ) {
    my %raw = $node->('raw');
    $rolling = blake2b_256( $rolling . $raw{iv} . $raw{ct} . $raw{tag} );
    _sendline($sock, join "\t",
        $raw{index},
        Crypt::Misc::encode_b64( $raw{iv}  ),
        Crypt::Misc::encode_b64( $raw{ct}  ),
        Crypt::Misc::encode_b64( $raw{tag} ),
        Crypt::Misc::encode_b64( $rolling  ),
    );
    $node = $raw{next_node};
}

# --- Protocol end ---
print $sock pack('n', 0);
print $sock "STOP";

$sock->flush;
    
my ($n, $buf);
$n = sysread $sock, $buf, 4096; ## just wait a little bit... really...
$n = sysread $sock, $buf, 4096; ## just wait a little bit... really...

exit 0;

# ---- Helper: send a line in correct framing ----
sub _sendline {
    my ($sock, $line) = @_;
    my $bytes = encode('UTF-8', $line);
    my $len   = length($bytes);
    die "Line exceeds ".MAX_LINE." bytes – abort\n" if $len > MAX_LINE;
    print $sock pack('n', $len), $bytes;
}

