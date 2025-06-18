package ev_socket;

########################################################################
# ev_socket.pm – create a UNIX-domain listener and serve a strict
#                binary protocol via AnyEvent
#                Protocol:
#                  • “START”   (5 bytes, literal)
#                  • TAG       (4 bytes, arbitrary ASCII)
#                  • zero-or-more repetitions of:
#                      ◦ LEN   (1 byte, 0-255)
#                      ◦ DATA  (LEN bytes)
#                  • LEN == 0  ⇒ terminate sequence, then
#                  • “STOP”    (4 bytes, literal)
#                Any deviation → immediate connection drop.
#                On successful completion, we reply with “OK\n”.
#
#      /usr/bin/printf 'STARTECHO\005HELLO\004WOOF\000STOP' | socat 
########################################################################

use strict;
use warnings;

use AnyEvent::Handle;
use IO::Socket::UNIX;
use Data::Dump qw(dump);
use make_unix_socket;
use get_peer_cred;
use gv_dir;

use Socket qw(SOMAXCONN);

#######################################################################
# add – register a listener for a given path and mode
#######################################################################
sub add {
    my ($g, %args) = @_;

    #–––––––––––––––––––––––– Parameter sanity ––––––––––––––––––––––––#
    my $path     = $args{path};
    my $abstract = $args{abstract} // 0;
    $path = gv_dir::abs($path) if defined $path && !$abstract;
    unless ($path) { warn "ev_socket::add requires 'path' parameter\n"; return }

    my $mode = $args{mode};
    unless (defined $mode) { warn "ev_socket::add requires 'mode' parameter\n"; return }

    # Prevent re-registering the same watcher
    if (   $g->{_watcher}
        && $g->{_watcher}->{ev_socket}
        && $g->{_watcher}->{ev_socket}->{$path})
    {
        warn "ev_socket::add: socket for $path already exists\n";
        return;
    }

    # Backlog
    my $backlog = $args{backlog} // SOMAXCONN;
    $backlog = SOMAXCONN if $backlog > SOMAXCONN;

    #––––––––––––––––––––––– Create listening socket –––––––––––––––––––#
    my $listener = make_unix_socket::make_unix_socket(
        path     => $path,
        mode     => $mode,
        backlog  => int($backlog),
        abstract => $abstract,
    ) or do {
        warn "Failed to set up socket at $path; see STDERR for details\n";
        return;
    };

    my $shown = $abstract ? "(abstract:$args{path})" : $path;
    print "Listening on $shown… [$listener]\n";

    #––––––––––––––––––––––––– Accept loop ––––––––––––––––––––––––––––#
    $g->{_watcher}->{ev_socket}->{$path} = AnyEvent->io(
        fh   => $listener,
        poll => 'r',
        cb   => sub {
            my $client = $listener->accept or return;

            # Non-optional peer-cred check
            my $creds = get_peer_cred::get_peer_cred($client);
            unless (   $creds
                    && defined $creds->{gid}
                    && defined $creds->{pid}
                    && defined $creds->{uid})
            {
                $client->close;
                return;
            }
            print STDERR "\n" . dump($creds) . "\n";

            my $hdl;
            $hdl = AnyEvent::Handle->new(
                fh       => $client,
                on_error => sub { 
                     my ( $handle, $fatal, $message ) = @_;
                     _eof_error ($handle, $fatal, $message); 
                     $hdl->destroy;
                     return;
                },
                on_eof   => sub { 
                     my ( $handle, $fatal, $message ) = @_;
                     _eof_error ($handle, $fatal, $message); 
                     $hdl->destroy;
                     return; 
                },
                rbuf_max => 4096,
                wbuf_max => 4096,
            );

            # Stash path for diagnostics & logging
            $hdl->{socket_path} = $shown;

            # Idle timeout
            $hdl->timeout(3);

            # State for the strict protocol
            $hdl->{_proto} = {
                tag   => undef,  # 4-byte TAG
                blobs => [],     # array-ref of binary chunks
            };

            # PRIME the binary protocol – wait for “START”
            $hdl->push_read( chunk => 5, \&_handle_start );
        }
    );

    return 1 if $g->{_watcher}->{ev_socket}->{$path};
    warn "ev_socket::add: failed to register watcher\n";
    return;
}

#######################################################################
# Private helpers for the strict binary protocol
#######################################################################

# EOF or ERROR 
sub _eof_error {
    my ($hdl, $fatal, $reason) = @_;
    my $src  = $hdl->{socket_path} // '<unknown>';
    $fatal   = $fatal              // '0';
    $reason  = $reason             // 'none';
    warn "[$src] [EOF/ERROR] [$fatal] [$reason].\n";
}


# Drop connection on any protocol violation
sub _protocol_error {
    my ($hdl, $reason) = @_;
    my $src = $hdl->{socket_path} // '<unknown>';
    warn "[$src] protocol error: $reason - closing socket\n";
    $hdl->destroy;
}

# STEP 1 – verify literal “START”
sub _handle_start {
    my ($hdl, $data) = @_;
    return _protocol_error($hdl, "expected 'START'") unless $data eq 'START';

    print "[START] - yep!\n";
    # Read TAG next (4 bytes)
    $hdl->push_read( chunk => 4, \&_handle_tag );
}

# STEP 2 – store TAG
sub _handle_tag {
    my ($hdl, $tag) = @_;
    $hdl->{_proto}->{tag} = $tag;

    print "[TAG] [$tag] - yep!\n";
    if (  uc($tag) eq 'DONE'  ) {
        $hdl->push_write("DONE\n");
        $hdl->push_shutdown;          # graceful half-close
        $hdl->on_drain( sub { shift->destroy } );
        return;
    }
    # First LEN byte (1 byte)
    $hdl->push_read( chunk => 1, \&_handle_len );
}

# STEP 3 – read LEN
sub _handle_len {
    my ($hdl, $len_byte) = @_;
    my $len = unpack 'C', $len_byte;   # unsigned char 0-255

    print "[LEN] == [$len] = waiting bytes...\n";
    if ($len == 0) {
        # Expect literal “STOP” afterwards
        $hdl->push_read( chunk => 4, \&_handle_tag );
        return;
    }

    # Sanity-check LEN against rbuf_max (defensive)
    return _protocol_error($hdl, "LEN $len exceeds rbuf_max")
        if $len > $hdl->{rbuf_max};

    # Read DATA of $len bytes
    $hdl->push_read( chunk => $len, sub {
        my ($hdl2, $binary) = @_;
        push @{ $hdl2->{_proto}->{blobs} }, $binary;

        # Loop back: expect next LEN
        $hdl2->push_read( chunk => 1, \&_handle_len );
    });
}

# STEP 4 – verify literal “STOP”, send ACK, and finish
sub _handle_stop {
    my ($hdl, $data) = @_;
    return _protocol_error($hdl, "expected 'STOP'") unless $data eq 'STOP';

    # Successful termination – you can now do something with the data
    my $src  = $hdl->{socket_path}        // '<unknown>';
    my $tag  = $hdl->{_proto}->{tag}      // '<undef>';
    my $cnt  = scalar @{ $hdl->{_proto}->{blobs} };
    my $size = 0; $size += length $_ for @{ $hdl->{_proto}->{blobs} };

    print "[$src] Received TAG=$tag, $cnt blob(s), total $size byte(s)\n";

    # Acknowledge the client and close once all data were sent
    $hdl->push_write("OK\n");
    $hdl->push_read( chunk => 4, \&_handle_tag );
    #$hdl->push_shutdown;          # graceful half-close
    #$hdl->on_drain( sub { shift->destroy } );
}

#######################################################################
# Legacy line-echo handler (unused by new protocol, kept for completeness)
#######################################################################
sub _handle_one_line {
    my ($hdl, $line) = @_;
    chomp $line;
    my $src = $hdl->{socket_path} // '<unknown>';
    print "[$src] == $line ==\n";

    $hdl->push_write("woof: $line\n");
    $hdl->push_read( line => \&_handle_one_line );
}

1;  # End of ev_socket.pm

