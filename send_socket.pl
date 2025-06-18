use strict;
use warnings;
use IO::Socket::UNIX;

my $abstract_name = "\0/tmp/woofwoof.sock";

my $sock = IO::Socket::UNIX->new(
    Type => SOCK_STREAM(),
    Peer => $abstract_name,
) or die "Can't connect: $!";

# Enable autoflush for writes
$sock->autoflush(1);

# Send raw payload
#my $payload = "STARTECHO" . chr(5) . "HELLO" . chr(4) . "WOOF" . chr(0) . "DATA"; # . chr(0) . "DONE";
my $payload = "STARTECHO" . chr(5) . "HELLO" . chr(4) . "WOOF" . chr(0) . "DATA" . chr(0) . "DONE";
print $sock $payload;

# Print all responses from server, live, forever
my $buf;
while (1) {
    my $n = sysread($sock, my $buf, 4096);
    last unless $n;
    chomp $buf;
    print "===> [$buf]\n";
    #print $sock $buf;   # with autoflush, this is sent immediately
}

# Optionally, never closes unless the server does

