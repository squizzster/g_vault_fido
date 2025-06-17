package ev_socket;

use strict;
use warnings;

use AnyEvent::Handle;
use IO::Socket::UNIX;
use Data::Dump qw(dump);
use make_unix_socket;
use get_peer_cred;
use gv_dir;

use Socket qw(SOMAXCONN);

########################################################################
# ev_socket.pm – create a UNIX-domain listener and serve simple line
#                request/response traffic via AnyEvent
########################################################################

sub add {
    my ($g, %args) = @_;

    #–––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
    # Parameter sanity
    #–––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
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

    # Backlog: default SOMAXCONN but never exceed it
    my $backlog = $args{backlog} // SOMAXCONN;
    $backlog = SOMAXCONN if $backlog > SOMAXCONN;

    #–––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
    # Create listening socket
    #–––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
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

    #–––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
    # Accept loop
    #–––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
    $g->{_watcher}->{ev_socket}->{$path} = AnyEvent->io(
        fh   => $listener,
        poll => 'r',
        cb   => sub {
            my $client = $listener->accept or return;

            # non-optional peer-cred check
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
                on_error => sub { $hdl->destroy },
                on_eof   => sub { $hdl->destroy },
                rbuf_max => 4096,
                wbuf_max => 4096,
            );

            # Stash path for diagnostics & logging
            $hdl->{socket_path} = $shown;

            # Idle timeout 
            $hdl->timeout(3);

            # Prime the read loop
            $hdl->push_read( line => \&_handle_one_line );
        }
    );

    return 1 if $g->{_watcher}->{ev_socket}->{$path};
    warn "ev_socket::add: failed to register watcher\n";
    return;
}

########################################################################
# _handle_one_line – called for every complete line from the client
########################################################################
sub _handle_one_line {
    my ($hdl, $line) = @_;

    chomp $line;                            # strip newline for cleaner log
    my $src = $hdl->{socket_path} // '<unknown>';
    print "[$src] == $line ==\n";

    $hdl->push_write("woof: $line\n");

    # Re-arm to wait for the next line
    $hdl->push_read( line => \&_handle_one_line );
}

1;  # End of ev_socket.pm

