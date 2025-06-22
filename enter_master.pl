#!/usr/bin/env perl
use strict;
use warnings;

use lib './lib';
use enter_master_password qw(get_master_key);


use IO::Socket::UNIX;
use IO::Handle;
use Encode qw(encode);

# Connect to abstract UNIX socket
my $abstract_name = "\0/tmp/woofwoof.sock";
my $sock = IO::Socket::UNIX->new(
    Type => SOCK_STREAM(),
    Peer => $abstract_name,
) or die "g-Vault FIFO is not running. [$!].";


# Run the key derivation and print result
my $hex_key = get_master_key();
print "$hex_key\n";

