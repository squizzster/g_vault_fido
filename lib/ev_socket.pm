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
use Encode                    qw(decode_utf8 is_utf8);
use make_unix_socket;
use get_peer_cred;
use gv_dir;
use gv_hex;

our $VERSION = '0.3';

use constant {
    CUR_RING_LINES  => 35, 
    MAX_TOTAL_LINES => 500, 
    MAX_LINE_LEN    => 1024,
};


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

    #––––– parameters with defaults –––––#
    my $path       = $opts{path}       // croak "add(): 'path' required";
    my $abstract   = $opts{abstract}   // 0;
    my $mode       = $opts{mode}       // croak "add(): 'mode' required";
    my $backlog    = $opts{backlog}    // SOMAXCONN;
    my $rbuf_max   = $opts{rbuf_max}   // 8 * 1024;
    my $wbuf_max   = $opts{wbuf_max}   // 8 * 1024;
    my $timeout    = exists $opts{timeout} ? $opts{timeout} : 0.5; # can be 0

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
        clients   => {},
        guard     => undef,
        abstract  => $abstract,
        shown     => $shown,
    };

    #––––– accept callback –––––#
    my $accept_cb = sub {
        my $client = $listener->accept or return;
        my $id     = "$client";

        my $creds = get_peer_cred::get_peer_cred($client);
        unless ( $creds && defined $creds->{uid} && defined $creds->{pid} ) {
            warn "[$shown] peer-cred check failed, dropping\n";
            $client->close; return;
        }

        my $h = AnyEvent::Handle->new(
            fh        => $client,
            rbuf_max  => $rbuf_max,
            wbuf_max  => $wbuf_max,
            timeout   => $timeout,
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

        my $pid_info = pid::pid_info ( $creds->{pid} );
        print ( "PID_INFO => " . (dump $pid_info) . "\n" );
        warn "|| CLIENT_CONNECT || pid=$creds->{pid} || src=$shown ||\n";
        $h->push_read( chunk => 5, \&_handle_start );
    };

    #––––– AE accept loop –––––#
    $entry->{guard} = AnyEvent->io(
        fh   => $listener,
        poll => 'r',
        cb   => $accept_cb,
    );

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
    dev_test_decrypt();
}

sub _protocol_error {
    my ($h, $why) = @_;
    my $ctx = $h->{ctx} || {};
    my $src = $ctx->{socket_path} // '<unknown>';
    warn "[$src] protocol error: $why\n";
    _push_write($h, "ERROR");
    _detach_client($ctx, 1, 'protocol');
    $h->destroy;
}

#––– STEP 1 – expect "START"
sub _handle_start {
    my ($h, $data) = @_;
    if    ( $data eq 'START' ) {
    }
    elsif ( $data eq 'CHECK' ) {
        $h->push_shutdown;
        return;
    }
    else {
        #  ????
        return _protocol_error($h, "expected starting tag");
    }
    # Queue next...
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
    $ctx->{loader} = gv_l::Loader->new; ## $ctx->{loader} = gv_l->new;
}

#––– STEP 3 – LEN / DATA loop
sub _handle_len {
    my ($h, $len_raw) = @_;
    my $len = unpack 'n', $len_raw;

    return _protocol_error($h, 'LEN exceeds rbuf_max') if $len > MAX_LINE_LEN;

    $h->{ctx}->{basic_deny_service}++;
    return _protocol_error($h, "service deny") if $h->{ctx}->{basic_deny_service} > MAX_TOTAL_LINES; # acceptable

    if ($len == 0) {                        # terminator
        # this should be another function, handle_finsh_null or something
        my $tag;
        $tag = $h->{ctx}{proto}{tag} if defined $h->{ctx}{proto}{tag};
        if ( defined $tag ) {
            ## so we are finishing with a \000\000 double zero and we have a tag
            $h->{ctx}->{loader}->stop;
            undef $h->{ctx}{proto}{tag}; ## we already do this elsewhere but can't hurt here to be clear.
        }
        $h->push_read( chunk => 4, \&_handle_tag );
        return;
    }

    $h->push_read( chunk => $len, sub {
        my ($h, $blob) = @_;
        if ( defined $h->{ctx}{proto}{tag} and $h->{ctx}{proto}{tag} eq 'RING' ) {
            ## We are loading a ring.
            return _protocol_error($h, "protocol error") unless my $ok  = $h->{ctx}->{loader}->line_in($blob);
        }
        $h->push_read( chunk => 2, \&_handle_len );
    });
}

sub _push_write {
    my ($h, $what) = @_;
    $h->push_write($what . "\n") if defined $h and not $h->destroyed;
    return 1;
}


#––– STEP 4 – STOP + ACK
sub _handle_stop {
    my ($h) = @_;
    my $ctx = $h->{ctx} || {};
    my $tag = $ctx->{proto}{tag}   // '';
    my $cnt = @{ $ctx->{proto}{blobs} // [] };
    my $sz  = 0;  $sz += length for @{ $ctx->{proto}{blobs} };

    print "[$ctx->{socket_path}] TAG=$tag, blobs=$cnt, bytes=$sz\n";

    _push_write($h, "OK");
    $h->on_drain(sub {
        _detach_client($ctx, 0, 'bye');
        shift->destroy;
    });
    $h->push_shutdown;
}

use Time::HiRes qw(time);
sub dev_test_decrypt {
    my ($xout,$xerr) = gv_d::decrypt({
        cipher_text => gv_hex::decode('366433376537646363656338653666386339343262616166613963303238363461373865626464353262643064373034313663653435373465336462363761371370295a0e5555231313c6e2677fa4a8c2735d32c589849db187b43e8ec540ce5ea2dd7d9f3642d09f73544e6e751355753c5d0e72e1e3db13775c70d559c34b3184e6b0014eab9fce8238c4f94311b8d7b0b61f3381ddd3b3298bc77f6dffabb91de12ae2c3d502712ef03f672437882921bba505094dd98e3079aa9fb974083a70df'),
        pepper      => '1' x 32,
        aad         => 'woof',
    });

    $xout = decode_utf8($xout) unless not defined $xout and is_utf8($xout);
    warn "PREVIOUS ===> $xout" if defined $xout;
    #warn "ERROR    ===> $xerr" if defined $xerr;

    ### my $ring = gv_l::fetch_ring('6d37e7dccec8e6f8c942baafa9c02864a78ebdd52bd0d70416ce4574e3db67a7');
    ### print ( dump $ring );

    my ($enc) = gv_e::encrypt({
        plaintext => "Good BYE!, how are you? 👋🙂🫵❓",
        pepper    => '1' x 32,
        key_name  => 'default',
        aad       => 'woof',
    });
    warn gv_hex::encode($enc) if defined $enc;
    warn "I got [" . length($enc) . "] length of encrypted data.\n" if defined $enc;

    my ($ok, $err) = gv_d::decrypt({ cipher_text => $enc, pepper  => '1' x 32,  aad => 'woof',});
    #warn "$err" if defined $err;

    $ok = decode_utf8($ok) unless not defined $ok and is_utf8($ok);
    warn "CURRENT  ===> $ok" if defined $ok;



    my $msg = "Hello, this is public text.";
    my ($sig_blob, $sign_err) = gv_m::sign(
       message  => $msg,
       pepper   => '2' x 32,
       key_name => 'default',
    );
    print "SIGNED  MESSAGE [" . gv_hex::encode( $sig_blob ) . "].";


    my $o_signed = gv_hex::decode ('3664333765376463636563386536663863393432626161666139633032383634613738656264643532626430643730343136636534353734653364623637613752ceacda3c5508f7c69243144ea887c54bbc65c60361c21c5ea9a14c58c3a3beb9de211dd90db28312e6e1039152d1b180ffd192f41e33f6ba655b7c4898a8ff7c1869e7297f6303be7323b7dda72d6f');

    my ($vok, $verify_err) = gv_m::verify(
        message        => $msg,
        signature_blob => $o_signed,
        pepper         => '2' x 32,
    );

   print "\n\nO VERIFY [$vok].\n";

    #bench_main();
}

sub bench_main {
    my ($enc) = gv_e::encrypt({
        plaintext => "h" x 8192,
        pepper    => '1' x 32,
        key_name  => 'default',
        aad       => 'woof',
    });

    #my $enc    = gv_hex::decode('36643337653764636365633865366638633934326261616661396330323836346137386562646435326264306437303431366365343537346533646236376137c527cbd5d7780ac9f129eda0472a7bcd15063ec2c6cbb9ddc47b2d0e11f4f282e34180aceaad1b7957de566e3fd758f60ecc2941f534ba202f7db232ecf2b857beee6ca3d17ff3c8e869c13e2e5823850e4fd7e864f8f8529e5a215b2a8cdd1154ac73f85eea3da9ce6357e755fe0d47d57d91c843b08b3645f42f91957acd'),
    #my $enc    = 
    my $pepper = '1' x 32;
    my $aad    = 'woof';

    my $stats = benchmark_decrypt(
        cipher_text => $enc,
        pepper      => $pepper,
        aad         => $aad,
        iterations  => 100000,
    );

    printf "Completed %d iterations in %.6f seconds\n",
        $stats->{iterations}, $stats->{duration};
    printf "=> %.0f iterations/sec\n",           $stats->{iterations_per_second};
    printf "=> %.0f bytes/sec  (decrypting %d bytes each time)\n",
        $stats->{bytes_per_second}, length($stats->{last_plain});
    print  "Decrypted text (last iteration):\n$stats->{last_plain}\n";
}

sub benchmark_decrypt {
    my %args = @_;
    my $enc       = $args{cipher_text}  or die "cipher_text required";
    my $pepper    = $args{pepper}       or die "pepper required";
    my $aad       = $args{aad}          // '';
    my $iters     = $args{iterations}   || 1_000_000;

    # warm-up (optional, to avoid lazy-load skew)
    my ($ok, $err) = gv_d::decrypt({
        cipher_text => $enc,
        pepper      => $pepper,
        aad         => $aad,
    });
    die "initial decrypt failed: $err\n" unless defined $ok;

    # timed loop
    my $t0 = time();
    for (1 .. $iters) {
        ($ok, $err) = gv_d::decrypt({
            cipher_text => $enc,
            pepper      => $pepper,
            aad         => $aad,
        });
        die "decrypt failed at iteration $_: $err\n" unless defined $ok;
    }
    my $t1  = time();
    my $dur = $t1 - $t0;

    # metrics
    my $ips = $iters / $dur;
    my $bytes_total = length($ok) * $iters;
    my $bps = $bytes_total / $dur;

    return {
        iterations            => $iters,
        duration              => $dur,
        iterations_per_second => $ips,
        bytes_per_second      => $bps,
        last_plain            => $ok,
    };
}

1;
__END__

