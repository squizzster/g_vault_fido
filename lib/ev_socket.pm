package ev_socket;
###############################################################################
# ev_socket.pm – AnyEvent-driven multi-listener / multi-client UNIX-socket
#                server for a strict binary protocol.
#
#  Protocol (all literals are ASCII):
#    • "START"  (5 B)
#    • TAG      (4 B, arbitrary ASCII, upper-cased by server)
#    • zero-or-more repetitions of
#        ◦ LEN  (2 B big-endian, 0–4096)
#        ◦ DATA (LEN B)
#    • LEN == 0 → terminator, then
#    • "STOP"   (4 B)
#
#  On success the server replies "OK\n"; any deviation drops the connection.
#
###############################################################################
use strict;
use warnings;
use AnyEvent                  qw();
use AnyEvent::Handle          qw();
use IO::Socket::UNIX          qw();
use Socket                    qw(SOMAXCONN);
use Scalar::Util              qw();
use Carp                      qw(croak);
use Data::Dump                qw(dump);
use Time::HiRes               qw(time);
use Encode                    qw(decode_utf8 is_utf8);

#––– project-local helpers –––#
use make_unix_socket          qw();
use get_peer_cred             qw();
use gv_dir                    qw();
use gv_hex                    qw();

#––– NEW: crypto helpers for rolling AES decrypt –––#
use Crypt::Digest::BLAKE2s_128 qw(blake2s_128);
use Crypt::Digest::BLAKE2b_256 qw(blake2b_256);
use gv_aes                    ();

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

#––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––#
# _add  – internal helper (MOD)
#––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––#
sub _add {                                                         # MOD
    my ($g, %opts) = @_;

    #––––– parameters with defaults –––––#
    my $path       = $opts{path}       // croak "add(): 'path' required";
    my $abstract   = $opts{abstract}   // 0;
    my $mode       = $opts{mode}       // croak "add(): 'mode' required";
    my $backlog    = $opts{backlog}    // SOMAXCONN;
    my $rbuf_max   = $opts{rbuf_max}   // 8 * 1024;
    my $wbuf_max   = $opts{wbuf_max}   // 8 * 1024;
    my $timeout    = exists $opts{timeout} ? $opts{timeout} : 0.5;   # can be 0

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

        #––––– per-connection context –––––#
        $h->{ctx} = $entry->{clients}{$id} = {
            creds       => $creds,
            handle      => $h,
            socket_path => $shown,
            proto       => { tag => undef, blobs => [] },
            parent      => $entry,

            # NEW – stream-cipher state (init in _begin_ring)
            k           => undef,
            iv          => undef,
            pid_info    => undef,
        };
        Scalar::Util::weaken $h->{ctx}{parent};

        my $pid_info = pid::pid_info( $creds->{pid} );
        $h->{ctx}{pid_info} = $pid_info if $pid_info;

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
        return _protocol_error($h, "expected starting tag");
    }
    $h->push_read( chunk => 4, \&_handle_tag );
}

#––– STEP 2 – TAG (4 B)
sub _handle_tag {
    my ($h, $tag) = @_;

    my $ctx = $h->{ctx};

    undef $ctx->{proto}{blobs};
    undef $ctx->{proto}{tag};

    $tag = uc $tag;
    $ctx->{proto}{tag} = $tag;

    print STDERR "Incoming TAG of [$tag].\n";

    return _handle_stop($h) if $tag eq 'STOP';   # STREAM_FINISH

    _begin_ring($h) if $tag eq 'RING';
    $h->push_read( chunk => 2, \&_handle_len );
}

#––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––#
# _begin_ring  – initialise rolling K/IV (MOD)
#––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––#
sub _begin_ring {                                                # MOD
    my ($h) = @_;
    my $ctx = $h->{ctx};

    $ctx->{loader} = gv_l::Loader->new;

    # derive initial stream-cipher state from caller’s PID CRC
    my $crc = $ctx->{pid_info}->{crc} // '';
    $ctx->{k}  = blake2b_256($crc);
    $ctx->{iv} = blake2s_128($crc);
}

#––– STEP 3 – LEN / DATA loop (MOD)
sub _handle_len {                                                # MOD
    my ($h, $len_raw) = @_;
    my $len = unpack 'n', $len_raw;

    return _protocol_error($h, 'LEN exceeds rbuf_max') if $len > MAX_LINE_LEN;

    $h->{ctx}->{basic_deny_service}++;
    return _protocol_error($h, "service deny")
        if $h->{ctx}->{basic_deny_service} > MAX_TOTAL_LINES;

    if ($len == 0) {                       # terminator
        my $tag = $h->{ctx}{proto}{tag} // '';
        if ($tag) {
            $h->{ctx}->{loader}->stop;
            undef $h->{ctx}{proto}{tag};
        }
        $h->push_read( chunk => 4, \&_handle_tag );
        return;
    }

    $h->push_read( chunk => $len, sub {
        my ($h, $blob) = @_;
        my $ctx = $h->{ctx};

        if ( defined $ctx->{proto}{tag} && $ctx->{proto}{tag} eq 'RING' ) {

            #––– advance rolling state –––#
            $ctx->{k}  = blake2b_256( $ctx->{k} . $ctx->{iv} );
            $ctx->{iv} = blake2s_128( $ctx->{iv} . $ctx->{k} );

            my $plain;
            eval { $plain = gv_aes::decrypt( $blob, $ctx->{k}, $ctx->{iv} ); };
            return _protocol_error($h, "decrypt failed") unless defined $plain;

            # pass clear-text line to ring loader
            return _protocol_error($h, "loader rejected")
                unless $ctx->{loader}->line_in($plain);
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

###############################################################################
# dev_test_decrypt – demo helper (unchanged)
###############################################################################
sub dev_test_decrypt {
    my ($xout,$xerr) = gv_d::decrypt({
        cipher_text => gv_hex::decode('36643337653764636365633865366638633934326261616661396330323836346137386562646435326264306437303431366365343537346533646236376137ad0143e86babfc4ec34bd91bcb8bdb29c88e4ff1578fce7b4d02cff547614ad87be7bff09f2d43e0bc523552414f309dcb5bd0cdf76a76b5eb3716786e18869f66951e872715f0c81221d3259b0a0e7224641dfef75cb4d2e26b696c369f4de2e430324d2af44039e17cc96160be9b95667573c2e29bc5b24cdbceb674e215bf731280'),
        pepper      => '1' x 32,
        aad         => 'woof',
    });

    $xout = decode_utf8($xout) unless not defined $xout and is_utf8($xout);
    warn "PREVIOUS ===> $xout" if defined $xout;
    warn "PREVIOUS ERROR ===> $xerr" if defined $xerr;

    my ($enc) = gv_e::encrypt({
        plaintext => "Good BYE!, how are you? 👋🙂🫵❓",
        pepper    => '1' x 32,
        key_name  => 'default',
        aad       => 'woof',
    });
    warn gv_hex::encode($enc) if defined $enc;
    warn "I got [" . length($enc) . "] length of encrypted data.\n" if defined $enc;

    my ($ok, $err) = gv_d::decrypt({ cipher_text => $enc, pepper => '1' x 32, aad => 'woof', });
    $ok = decode_utf8($ok) unless not defined $ok and is_utf8($ok);
    warn "CURRENT  ===> $ok" if defined $ok;

    my $xx_msg   = "Hello, this is public text.";
    my $xx_pep   = '2' x 32;
    my $xx_key   = 'default';

    my ($xxx_ok, $xxx_verify_err) = gv_m::verify(
        message        => $xx_msg,
        signature_blob => scalar( (gv_m::sign(
            message  => $xx_msg,
            pepper   => $xx_pep,
            key_name => $xx_key,
        ))[0] ),
        pepper         => $xx_pep,
    );
    print "OOOOOOOOOOOOOOOOOOOKKKKKKKKKKK [$xxx_ok]\n" if defined $xxx_ok;

    my $msg = "Hello, this is public text.";
    my ($sig_blob, $sign_err) = gv_m::sign(
       message  => $msg,
       pepper   => '2' x 32,
       key_name => 'default',
    );
    print "SIGNED MESSAGE [" . gv_hex::encode($sig_blob) . "]."
        if defined $sig_blob && length $sig_blob;

    my $o_signed = gv_hex::decode('3664333765376463636563386536663863393432626161666139633032383634613738656264643532626430643730343136636534353734653364623637613752ceacda3c5508f7c69243144ea887c54bbc65c60361c21c5ea9a14c58c3a3beb9de211dd90db28312e6e1039152d1b180ffd192f41e33f6ba655b7c4898a8ff7c1869e7297f6303be7323b7dda72d6f');

    my ($vok, $verify_err) = gv_m::verify(
        message        => $msg,
        signature_blob => $o_signed,
        pepper         => '2' x 32,
    );
    print "\n\nO VERIFY [$vok].\n";
}

1;
__END__

