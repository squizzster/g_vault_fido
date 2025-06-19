package ev_socket;
###############################################################################
# ev_socket.pm – AnyEvent-driven multi-listener / multi-client UNIX-socket
#                server for a strict binary protocol.
#
#  Protocol (all literals are ASCII):
#    • "START"  (5 B)
#    • TAG      (4 B, arbitrary ASCII, upper-cased by server)
#    • zero-or-more repetitions of
#        ◦ LEN  (2 B, big-endian, 0–4096)
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
use Data::Dumper              qw(Dumper);
use make_unix_socket;
use get_peer_cred;
use gv_dir;
use hex;

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
                rbuf_max  => 8 * 1024,
                wbuf_max  => 8 * 1024,
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
    test_decrypt();
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

    my $ctx = $h->{ctx};

    ## Reset:
    undef $ctx->{proto}{blobs};
    undef $ctx->{proto}{tag};

    $tag = uc $tag;
    $ctx->{proto}{tag} = $tag;

    print STDERR "Incoming TAG of [$tag].\n";

    return _handle_stop($h) if $tag eq 'STOP'; # RETURN HERE as this is STREAM_FINISH!

     _begin_ring ($h) if $tag eq 'RING';
    $h->push_read( chunk => 2, \&_handle_len );
}

sub _begin_ring {
    my ($h) = @_;
    my $ctx = $h->{ctx};
    $ctx->{loader} = gv_l->new;
}


#––– STEP 3 – LEN / DATA loop
sub _handle_len {
    my ($h, $len_raw) = @_;
    my $len = unpack 'n', $len_raw;

    return _protocol_error($h, 'LEN exceeds rbuf_max')
        if $len > $h->{rbuf_max};

    if ($len == 0) {                        # terminator
        # this should be another function, handle_finsh_null or something
        my $tag;
        $tag = $h->{ctx}{proto}{tag} if defined $h->{ctx}{proto}{tag};
        if ( defined $tag ) {
            ## so we are finishing with a \000\000 double zero and we have a tag
            $h->{ctx}->{loader}->_stop;
            undef $h->{ctx}{proto}{tag}; ## we already do this elsewhere but can't hurt here to be clear.
        }
        $h->push_read( chunk => 4, \&_handle_tag );
        return;
    }

    $h->push_read( chunk => $len, sub {
        my ($h, $blob) = @_;
        if ( defined $h->{ctx}{proto}{tag} and $h->{ctx}{proto}{tag} eq 'RING' ) {
            ## We are loading a ring.
            my $ctx = $h->{ctx};
            return _protocol_error($h, "protocol error") unless my $ok  = $ctx->{loader}->_line_in($blob);
        }
        $h->push_read( chunk => 2, \&_handle_len );
    });
}

#––– STEP 4 – STOP + ACK
sub _handle_stop {
    my ($h) = @_;
    my $ctx = $h->{ctx} || {};
    my $tag = $ctx->{proto}{tag}   // '';
    my $cnt = @{ $ctx->{proto}{blobs} // [] };
    my $sz  = 0;  $sz += length for @{ $ctx->{proto}{blobs} };

    print "[$ctx->{socket_path}] TAG=$tag, blobs=$cnt, bytes=$sz\n";

    $h->push_write("OK\n");
    $h->on_drain(sub {
        _detach_client($ctx, 0, 'bye');
        shift->destroy;
    });
    $h->push_shutdown;
}

sub test_decrypt {
    my ($xout,$xerr) = gv_d::decrypt({
        cipher_text => hex::decode('623936313362353937373366343137656364373234363337366232666438393936656130386437663665613366343837623832376661663661386432333030393b40e0987d6dd75f222dfedfd7caf0402d19f86aca0a131bc3854105c3727e03fea25112e98a4be56399536069d1d4787d90a3bdf1cf46f93382a1a69404ee26efc5a791f7c4d47531ff9f7306e1738a4adf79db8125a300655332e9591f304d6a49da43299e4c6eb83aa79f64ff5c07865e24cfe8593038189b7634bf75b434ddc2992337b6aca18ac09c1024f665cccd6e0226e04bbe6dcbee69d00d98bc41faf65de957987154f5b1c47228aa8f9ae0b9c18f4d7bc23e822b1cda8d5a58073519ca919a7d24077362847f59b8a2d96154c75fabb68900b38128e2c52239aa129f545779b33e1f7b54885922a68ba9c09b5f498c926a01f04bbb487e9184699dcf8f2477553a62c674cdfac5d36c038f8520625ba812ce658409b4083513fcbe6df0c09d06fa7c5d8fa4b9e2698be7c8d2eeb582a6a81052f8e16fb409da1b8b17a6ca68e758c1c3d156392697a08c11e2a3dc3e78f17017003549d3f5c9d7c1f02efbf3'),
        pepper      => '12345678' x 4,
        aad         => 'woof',
    });
    warn $xout if defined $xout;
    warn $xerr if defined $xerr;

    my ($enc) = gv_e::encrypt({
        plaintext => "hello, how are you?",
        pepper    => '1' x 32,
        key_name  => 'memory',
        aad       => 'woof',
    });
    warn "I got [" . length($enc) . "] length of encrypted data.\n";
    my ($ok) = gv_d::decrypt({ cipher_text => $enc, pepper  => '1' x 32,  aad => 'woof',});
    warn "$ok";
}

1;
__END__

