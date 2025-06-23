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

use gv_c ();
use pid  ();
use enter_master_password qw(get_master_key);
use Crypt::Misc  ();
use Crypt::Digest::BLAKE2s_128 qw(blake2s_128);
use Crypt::Digest::BLAKE2b_256 qw(blake2b_256 blake2b_256_hex);
use gv_random;
use gv_aes;
use Data::Dump qw(dump);
use constant {
    SOCKET_PATH => "\0/tmp/woofwoof.sock",
    MAX_LINE    => 4096,
};

exit main();

sub main {
    my $pid = pid::pid_info($$);
    check_daemon_is_alive();

    my ( $sock, $ring ) = setup_and_build_ring();

    if ( $sock and $ring ) {
        stream_cipher_ring( $sock, $ring, $pid );
        if  ( wait_for_acknowledgment($sock) ) {
            print "OK\n";
        }
        else {
            print STDERR ("ERROR\n");
            return 1;
        }
    }
    else {
        print STDERR ("ERROR\n");
        return 1;
    }
    return 0;
}

sub check_daemon_is_alive {
    my $sock = IO::Socket::UNIX->new(
        Type => SOCK_STREAM(),
        Peer => SOCKET_PATH,
    ) or die "Cannot connect to daemon at ".SOCKET_PATH.": $!\n";
    print $sock "CHECK\n"; ## tells the daemon we were just checking 
    # immediately close
    $sock->close;
}

sub setup_and_build_ring {
    my ($ring_name, $master_hex) = get_master_key();
    my ( $ring, $err ) = gv_c::build_cipher_ring(
        name          => $ring_name,
        master_secret => pack('H*', $master_hex),
    );
    die "build_cipher_ring failed: $err\n" if $err;
    my $sock = IO::Socket::UNIX->new(
        Type => SOCK_STREAM(),
        Peer => SOCKET_PATH,
    ) or die "Cannot connect to daemon at ".SOCKET_PATH.": $!\n";
    $sock->autoflush(1);
    return ( $sock, $ring );
}

sub stream_cipher_ring {
    my ( $sock, $ring, $pid ) = @_;

    my $s = {
      sock => $sock,
      k    => blake2b_256($pid->{crc}),
      iv   => blake2s_128($pid->{crc}),
    };

    print $sock "START";
    print $sock "RING";

    my $rolling = 'save_cipher_ring:';

    _sendline( $s, $ring->{name} );

    $rolling = blake2b_256_hex( $rolling . $ring->{name_hash} );
    _sendline( $s, join "\t", $ring->{name_hash}, $rolling );

    $rolling = blake2b_256_hex( $rolling . $ring->{mac_key} );
    _sendline( $s, join "\t", Crypt::Misc::encode_b64( $ring->{mac_key} ), $rolling );

    $rolling = blake2b_256_hex( $rolling . $ring->{aes_key} );
    _sendline( $s, join "\t", Crypt::Misc::encode_b64( $ring->{aes_key} ), $rolling );

    my %seen;
    my $node = $ring->{f};
    while ( $node && !$seen{ refaddr $node }++ ) {
        my %raw = $node->('raw');
        $rolling = blake2b_256( $rolling . $raw{iv} . $raw{ct} . $raw{tag} );
        _sendline(
            $s,
            join "\t",
            $raw{index},
            Crypt::Misc::encode_b64( $raw{iv} ),
            Crypt::Misc::encode_b64( $raw{ct} ),
            Crypt::Misc::encode_b64( $raw{tag} ),
            Crypt::Misc::encode_b64($rolling),
        );
        $node = $raw{next_node};
    }

    print $sock pack( 'n', 0 );    # end marker
    print $sock "STOP";
    $sock->flush;
}

sub wait_for_acknowledgment {
    my ($sock) = @_;
    my ($n, $buf);
    $n = sysread $sock, $buf, MAX_LINE;
    chomp $buf;
    return 1 if $buf eq 'OK';
    return;
}

sub _sendline {
    my ( $s, $line ) = @_;

    ## rotate our key....
    $s->{k}  = blake2b_256 ( $s->{k}  . $s->{iv} );
    $s->{iv} = blake2s_128 ( $s->{iv} . $s->{k}  );

    my $bytes = encode( 'UTF-8', $line );

    my $enc_b = gv_aes::encrypt ($line, $s->{k}, $s->{iv});

    my $len   = length($enc_b);
    die "Line exceeds ".MAX_LINE." bytes – abort\n" if $len > MAX_LINE;
    $s->{sock}->print( pack('n', $len), $enc_b );
}

