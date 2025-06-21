#!/usr/bin/env perl

# ==============================================================================
# -- PRAGMAS AND MODULES -------------------------------------------------------
# ==============================================================================

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

# ==============================================================================
# -- CONSTANTS -----------------------------------------------------------------
# ==============================================================================

use constant {
    SOCKET_PATH => "\0/tmp/woofwoof.sock",
    MAX_LINE    => 4096,
};

# Execute the main subroutine and exit with its status code.
exit main();



# ==============================================================================
# -- MAIN EXECUTION ------------------------------------------------------------
# ==============================================================================

# The main logic is a clear sequence of steps.
sub main {
    # Phase 1: Fail fast if the daemon is not running.
    check_daemon_is_alive();

    # Phase 2: Get credentials, connect, and build the data structure.
    my ( $sock, $ring ) = setup_and_build_ring();

    # Phase 3: Send the data structure to the daemon over the socket.
    stream_cipher_ring( $sock, $ring );

    # Phase 4: Wait for a confirmation from the daemon before exiting.
    wait_for_acknowledgment($sock);

    return 0;
}


# ==============================================================================
# -- SUBROUTINES ---------------------------------------------------------------
# ==============================================================================

# ------------------------------------------------------------------------------
# -- Phase 1: Pre-Connection Check
# ------------------------------------------------------------------------------
# Ensures the daemon is listening before asking the user for credentials.
sub check_daemon_is_alive {
    IO::Socket::UNIX->new(
        Type => SOCK_STREAM(),
        Peer => SOCKET_PATH,
    ) or die "Cannot connect to daemon at ".SOCKET_PATH.": $!\n";
    # The socket handle is not used further and is immediately discarded.
}

# ------------------------------------------------------------------------------
# -- Phase 2: Setup and Cipher Ring Creation
# ------------------------------------------------------------------------------
# Connects to the daemon, gets user credentials, and builds the cipher ring.
# Returns the active socket handle and the completed ring structure.
sub setup_and_build_ring {
    # Get user credentials.
    my ($ring_name, $master_hex) = get_master_key();

    # Build the in-memory cipher ring from credentials.
    my ( $ring, $err ) = gv_c::build_cipher_ring(
        name          => $ring_name,
        master_secret => pack('H*', $master_hex),
    );
    die "build_cipher_ring failed: $err\n" if $err;

    # Establish the primary socket connection for data transfer.
    my $sock = IO::Socket::UNIX->new(
        Type => SOCK_STREAM(),
        Peer => SOCKET_PATH,
    ) or die "Cannot connect to daemon at ".SOCKET_PATH.": $!\n";
    $sock->autoflush(1);

    return ( $sock, $ring );
}

# ------------------------------------------------------------------------------
# -- Phase 3: Stream Cipher Ring to Daemon
# ------------------------------------------------------------------------------
# Implements the protocol for sending the cipher ring data.
sub stream_cipher_ring {
    my ( $sock, $ring ) = @_;

    # --- Protocol Start ---
    print $sock "START";
    print $sock "RING";

    # --- Streaming Data with Rolling Hash ---
    my $rolling = 'save_cipher_ring:';

    # 3a. Ring name
    _sendline( $sock, $ring->{name} );

    # 3b. Name hash
    $rolling = blake2b_256_hex( $rolling . $ring->{name_hash} );
    _sendline( $sock, join "\t", $ring->{name_hash}, $rolling );

    # 3c. MAC key
    $rolling = blake2b_256_hex( $rolling . $ring->{mac_key} );
    _sendline( $sock, join "\t", Crypt::Misc::encode_b64( $ring->{mac_key} ), $rolling );

    # 3d. AES key
    $rolling = blake2b_256_hex( $rolling . $ring->{aes_key} );
    _sendline( $sock, join "\t", Crypt::Misc::encode_b64( $ring->{aes_key} ), $rolling );

    # 3e. All encrypted nodes
    my %seen;
    my $node = $ring->{f};
    while ( $node && !$seen{ refaddr $node }++ ) {
        my %raw = $node->('raw');
        $rolling = blake2b_256( $rolling . $raw{iv} . $raw{ct} . $raw{tag} );
        _sendline(
            $sock,
            join "\t",
            $raw{index},
            Crypt::Misc::encode_b64( $raw{iv} ),
            Crypt::Misc::encode_b64( $raw{ct} ),
            Crypt::Misc::encode_b64( $raw{tag} ),
            Crypt::Misc::encode_b64($rolling),
        );
        $node = $raw{next_node};
    }

    # --- Protocol End ---
    print $sock pack( 'n', 0 );    # Zero-length frame to signify end of data
    print $sock "STOP";
    $sock->flush;
}

# ------------------------------------------------------------------------------
# -- Phase 4: Wait for Server Acknowledgment
# ------------------------------------------------------------------------------
# Pauses execution to wait for a response from the daemon.
sub wait_for_acknowledgment {
    my ($sock) = @_;
    my ($n, $buf);
    $n = sysread $sock, $buf, MAX_LINE;
}

# ------------------------------------------------------------------------------
# -- Helper Subroutine
# ------------------------------------------------------------------------------
# Sends a line of data with a 2-byte network-order length prefix.
sub _sendline {
    my ( $sock, $line ) = @_;
    my $bytes = encode( 'UTF-8', $line );
    my $len   = length($bytes);
    die "Line exceeds ".MAX_LINE." bytes – abort\n" if $len > MAX_LINE;
    print $sock pack( 'n', $len ), $bytes;
}
