#!/usr/bin/env perl
use strict;
use warnings;

use lib 'lib';
use get_peer_cred;
use make_unix_socket;
use AnyEvent::Handle;
use IO::Socket::UNIX;
use AnyEvent;
use Data::Dump qw(dump);

# Create the listening socket (600 perms, backlog = 10)
my $SOCK_PATH = '/tmp/woofwoof.sock';
my $listener  = make_unix_socket::make_unix_socket(
    path    => $SOCK_PATH,
    mode    => 0600,
    backlog => 10,
);

unless ($listener) {
    die "Failed to set up socket at $SOCK_PATH; see STDERR for details\n";
}

print "Listening on $SOCK_PATH... [$listener]\n";
# Accept loop via AnyEvent
my $accept_watcher;
$accept_watcher = AnyEvent->io(
    fh   => $listener,
    poll => 'r',
    cb   => sub {
        my $client = $listener->accept or return;
        my $creds  = get_peer_cred::get_peer_cred($client);
        unless ( $creds && defined $creds->{gid} && defined $creds->{pid} && defined $creds->{uid}) {
            $client->close;
            return;
        }

        print STDERR "\n" . ( dump $creds ) . "\n";

        # Wrap with AnyEvent::Handle for async reads/writes
        my $hdl;
        $hdl = AnyEvent::Handle->new(
            fh     => $client,
            on_error => sub {
                $hdl->destroy;
            },
            on_eof => sub {
                $hdl->destroy;
            },
        );
        $hdl->push_read( line => sub {
            my ($hdl, $line) = @_;
            $hdl->push_write("woof: $line\n");
            $hdl->destroy; # Close after single reply
        });
    }
);

AnyEvent->condvar->recv; # Run forever
