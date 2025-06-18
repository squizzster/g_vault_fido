package ev_socket;
###############################################################################
# ev_socket.pm – AnyEvent-driven multi-listener / multi-client UNIX-socket
#                server for a strict binary protocol.
#
#  Protocol (all literals are ASCII):
#    • "START"  (5 B)
#    • TAG      (4 B, arbitrary ASCII, upper-cased by server)
#    • zero-or-more repetitions of
#        ◦ LEN  (1 B, 0-255)
#        ◦ DATA (LEN B)
#    • LEN == 0 → terminator, then
#    • "STOP"   (4 B)
#
#  On success the server replies "OK\n"; any deviation drops the connection.
#
#  Public API
#  ----------
#    add( $g, %opts )
#      path      => '/tmp/foo.sock' | 'myname'
#      abstract  => 0|1
#      mode      => file-mode (octal)
#      backlog   => listen backlog (default SOMAXCONN)
#
#    remove( $g, $path )
#      Gracefully drops the listener and all of its clients.
#
#    shutdown_all( $g )
#      Convenience helper that closes every listener and client.
#
###############################################################################
use strict;
use warnings;

use AnyEvent                  qw();
use AnyEvent::Handle          qw();
use IO::Socket::UNIX          qw();
use Socket                    qw(SOMAXCONN);
use Scalar::Util              qw(weaken);
use Carp                      qw(croak);
use Data::Dump                qw(dump);
use make_unix_socket;
use get_peer_cred;
use gv_dir;

our $VERSION = '0.3';

###############################################################################
# add( $g, %opts ) – register a new listening socket
###############################################################################

sub add { 
    local $@; 
    my $r = eval { _add(@_) }; 
    $@ ? (warn "add failed: $@", undef) : $r 
}

sub _add {
    my ($g, %opts) = @_;

    #––––– parameters –––––#
    my $path     = $opts{path}     // croak "add(): 'path' required";
    my $abstract = $opts{abstract} // 0;
    my $mode     = $opts{mode}     // croak "add(): 'mode' required";
    my $backlog  = $opts{backlog}  // SOMAXCONN;

    $path = gv_dir::abs($path) unless $abstract;
    $backlog = SOMAXCONN if $backlog > SOMAXCONN;

    #––––– init global bucket –––––#
    $g->{ev_socket} //= { listeners => {} };

    #––––– de-dup –––––#
    return if $g->{ev_socket}{listeners}{$path};

    #––––– create socket –––––#
    my $listener = make_unix_socket::make_unix_socket(
        path     => $path,
        mode     => $mode,
        backlog  => $backlog,
        abstract => $abstract,
    ) or croak "failed to create socket at $path";

    my $shown = $abstract ? "(abstract:$path)" : $path;
    print "Listening on $shown [$listener]\n";

    #––––– registry entry –––––#
    my $entry = $g->{ev_socket}{listeners}{$path} = {
        listener  => $listener,
        clients   => {},                 # key = "$client"
        guard     => undef,              # AE watcher
        abstract  => $abstract,
    };

    #––––– AE accept loop –––––#
    $entry->{guard} = AnyEvent->io(
        fh   => $listener,
        poll => 'r',
        cb   => sub {
            my $client = $listener->accept or return;
            my $id     = "$client";

            my $creds = get_peer_cred::get_peer_cred($client);
            unless ( $creds && defined $creds->{uid} ) {
                warn "[$shown] peer-cred check failed, dropping\n";
                $client->close; return;
            }

            my $h = AnyEvent::Handle->new(
                fh        => $client,
                rbuf_max  => 4 * 1024,
                wbuf_max  => 4 * 1024,
                timeout   => 10,
                on_error  => \&_eof_error,
                on_eof    => \&_eof_error,
            );

            $h->{ctx} = $entry->{clients}{$id} = {
                creds       => $creds,
                handle      => $h,
                socket_path => $shown,
                proto       => { tag => undef, blobs => [] },
                parent      => $entry,
            };
            weaken $h->{ctx}{parent};

            warn "|| CLIENT_CONNECT || pid=$creds->{pid} || src=$shown ||\n";
            # prime protocol
            $h->push_read( chunk => 5, \&_handle_start );
        });

    return 1;
}

###############################################################################
# remove( $g, $path ) – drop a single listener
###############################################################################
sub remove {
    my ($g, $path) = @_;
    return unless $g && $g->{ev_socket} && $g->{ev_socket}{listeners}{$path};

    my $entry = delete $g->{ev_socket}{listeners}{$path};

    $_->{handle}->destroy for values %{ $entry->{clients} };
    $entry->{guard}  = undef;
    $entry->{listener}->close if $entry->{listener};
    return 1;
}

###############################################################################
# shutdown_all( $g ) – stop everything
###############################################################################
sub shutdown_all {
    my ($g) = @_;
    return unless $g && $g->{ev_socket};

    remove( $g, $_ ) for keys %{ $g->{ev_socket}{listeners} };
    delete $g->{ev_socket};
    return 1;
}

###############################################################################
# INTERNAL HELPERS
###############################################################################
sub _eof_error {
    my ($h, $fatal, $msg) = @_;

    # When called via on_eof $fatal/$msg are undef ⇒ normal EOF.
    my $ctx = $h->{ctx} || {};

    if ( defined $fatal ) {
        $msg = $msg // 'unknown';
        _detach_client($ctx, 1, $msg);
    } else {
        _detach_client($ctx, 0, 'eof');
    }

    $h->destroy;
}

sub _detach_client {
    my ($ctx, $is_error, $why) = @_;
    return unless $ctx && $ctx->{parent};
    my $src = $ctx->{socket_path} // '<unknown>';
    my $pid = $ctx->{creds}->{pid};
    warn "|| CLIENT_CLOSED  || pid=$pid || src=$src || is_error=$is_error || why=$why ||\n";
    delete $ctx->{parent}{clients}{ "$ctx->{handle}{fh}" };
}

sub _protocol_error {
    my ($h, $why) = @_;
    my $ctx = $h->{ctx} || {};
    my $src = $ctx->{socket_path} // '<unknown>';
    warn "[$src] protocol error: $why\n";
    _detach_client($ctx, 1, 'protocol');
    $h->destroy;
}

#––– STEP 1 – expect "START"
sub _handle_start {
    my ($h, $data) = @_;
    return _protocol_error($h, "expected START") unless $data eq 'START';
    $h->push_read( chunk => 4, \&_handle_tag );
}

#––– STEP 2 – TAG (4 B)
sub _handle_tag {
    my ($h, $tag) = @_;
    $tag = uc $tag;
    $h->{ctx}{proto}{tag} = $tag;
    print STDERR "Incoming TAG of [$tag].\n";

    return _handle_stop($h) if $tag eq 'STOP';
    $h->push_read( chunk => 1, \&_handle_len );
}

#––– STEP 3 – LEN / DATA loop
sub _handle_len {
    my ($h, $len_raw) = @_;
    my $len = unpack 'C', $len_raw;

    return _protocol_error($h, 'LEN exceeds rbuf_max')
        if $len > $h->{rbuf_max};

    if ($len == 0) {                        # terminator
        $h->push_read( chunk => 4, \&_handle_tag );
        return;
    }

    $h->push_read( chunk => $len, sub {
        my ($h, $blob) = @_;
        push @{ $h->{ctx}{proto}{blobs} }, $blob;
        $h->push_read( chunk => 1, \&_handle_len );
    });
}

#––– STEP 4 – STOP + ACK
sub _handle_stop {
    my ($h) = @_;
    my $ctx = $h->{ctx} || {};
    my $tag = $ctx->{proto}{tag}   // '';
    my $cnt = @{ $ctx->{proto}{blobs} };
    my $sz  = 0;  $sz += length for @{ $ctx->{proto}{blobs} };

    print "[$ctx->{socket_path}] TAG=$tag, blobs=$cnt, bytes=$sz\n";

    $h->push_write("OK\n");
    $h->on_drain(sub {
        _detach_client($ctx, 0, 'bye');
        shift->destroy;
    });
    $h->push_shutdown;
}

1;
__END__

