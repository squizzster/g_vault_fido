#!/usr/bin/env perl
use strict;
use warnings;
use IO::Socket::UNIX;
use IO::Handle;
use Encode qw(encode);
use FindBin;
use lib "$FindBin::Bin/lib";
use enter_master_password qw(get_master_key);
use gv_c qw(build_cipher_ring);
use gv_s (); # import manually
use gv_random;

# -- 1. Ask for master password and vault name
my $master_key_hex = get_master_key();   # Returns hex string
my $master_secret  = pack('H*', $master_key_hex); # to raw bytes

# Optional: ask vault name here if you want, or derive from get_master_key's logic

my $vault_name = 'default'; # Or however you want to select it

# -- 2. Create the cipher ring
my ($ring, $err) = gv_c::build_cipher_ring(
    name          => $vault_name,
    master_secret => $master_secret
);
die "Failed to build cipher ring: $err\n" unless $ring;

# -- 3. Connect to the UNIX socket for sending
my $abstract_name = "\0/tmp/woofwoof.sock";
my $sock = IO::Socket::UNIX->new(
    Type => SOCK_STREAM(),
    Peer => $abstract_name,
) or die "Can't connect to daemon: $!";

$sock->autoflush(1);

# -- 4. Send headers/commands as needed
print $sock "START";
print $sock "RING";

# -- 5. Use a variant of save_cipher_ring that writes to $sock, not a file
#     We'll adapt gv_s::save_cipher_ring logic:
save_cipher_ring_to_fh($ring, $sock);

# Send terminator as per protocol
print $sock pack('n', 0);
print $sock "STOP";

# -- 6. Read any responses
while (1) {
    my $n = sysread($sock, my $buf, 4096);
    last unless $n;
    chomp $buf;
    print "===> [$buf]\n";
}

# -- Helper: like gv_s::save_cipher_ring but to $fh
sub save_cipher_ring_to_fh {
    my ($ring, $fh) = @_;
    require Crypt::Digest::BLAKE2b_256;
    require Crypt::Misc;
    require Scalar::Util;
    my $current_blake = 'save_cipher_ring:';
    print {$fh} $ring->{name}, "\n";
    $current_blake = Crypt::Digest::BLAKE2b_256::blake2b_256_hex( $current_blake . $ring->{name_hash} );
    print {$fh} $ring->{name_hash}, "\t", $current_blake, "\n";
    $current_blake = Crypt::Digest::BLAKE2b_256::blake2b_256_hex( $current_blake . $ring->{mac_key} );
    print {$fh} Crypt::Misc::encode_b64( $ring->{mac_key} // q{} ), "\t", $current_blake, "\n";
    $current_blake = Crypt::Digest::BLAKE2b_256::blake2b_256_hex( $current_blake . $ring->{aes_key} );
    print {$fh} Crypt::Misc::encode_b64( $ring->{aes_key} ), "\t", $current_blake, "\n";
    my %seen;
    my $node = $ring->{f};
    while ( $node && !$seen{ Scalar::Util::refaddr $node }++ ) {
        my %raw = $node->('raw');
        $current_blake = Crypt::Digest::BLAKE2b_256::blake2b_256($current_blake . $raw{iv} . $raw{ct} . $raw{tag});
        print {$fh} join("\t",
            $raw{index},
            Crypt::Misc::encode_b64($raw{iv}),
            Crypt::Misc::encode_b64($raw{ct}),
            Crypt::Misc::encode_b64($raw{tag}),
            Crypt::Misc::encode_b64($current_blake),
        ), "\n";
        $node = $raw{next_node};
    }
    # (NO close $fh!)
    return 1;
}

