package make_unix_socket;

use strict;
use warnings;

use Socket qw(
    AF_UNIX SOCK_STREAM SOCK_CLOEXEC SOMAXCONN sockaddr_un
    SOL_SOCKET SO_PASSCRED
);
use Fcntl         qw(:mode F_SETFD FD_CLOEXEC);
use File::Basename qw(dirname);
use File::Path     qw(make_path);
use File::Spec     qw(catdir splitdir);
use Carp           qw(carp);
use IO::Socket::UNIX ();                   # for method table

#----------------------------------------------------------------------#
# make_unix_socket(%opts)
#   Creates a hardened, file-backed AF_UNIX listening socket.
#   Returns an IO::Socket::UNIX object on success, undef on failure.
#
# Options (all optional except path):
#   path    => '/run/myapp/app.sock'   # REQUIRED
#   backlog => SOMAXCONN               # default SOMAXCONN
#   mode    => 0600                    # default 0600
#   uid     => $>,                     # default -1 (no chown)
#   gid     => $(                      # default -1 (no chown)
#----------------------------------------------------------------------#
########################################################################
# make_unix_socket.pm
########################################################################
sub make_unix_socket {
    my (%opt)     = @_;
    my $sock_path = $opt{path};
    my $backlog   = exists $opt{backlog}  ? $opt{backlog}  : SOMAXCONN;
    my $mode      = exists $opt{mode}     ? $opt{mode}     : 0600;
    my $uid       = exists $opt{uid}      ? $opt{uid}      : -1;
    my $gid       = exists $opt{gid}      ? $opt{gid}      : -1;
    my $abstract  = exists $opt{abstract} ? $opt{abstract} : 0;   # <-- NEW

    # When abstract => 1, ensure path is NUL-prefixed; callers may pass it either way.
    if ($abstract) {
        $sock_path = "\0$sock_path" if defined $sock_path && substr($sock_path, 0, 1) ne "\0";
    }

    # Save & tighten umask during the sensitive window
    my $old_umask = umask();
    umask 077;

    # 1) Path sanity
    unless (defined $sock_path && length $sock_path) {
        carp "Socket path is required";
        umask $old_umask;
        return undef;
    }
    if (length($sock_path) >= 108) {           # abstract & pathname share the same limit
        carp "Socket path too long for sockaddr_un (max 107 bytes plus NUL)";
        umask $old_umask;
        return undef;
    }

    # 2-3) Filesystem checks – **skip entirely for abstract sockets**
    unless ($abstract) {
        # Ensure directory tree is secure
        unless (_ensure_secure_directory(dirname($sock_path))) {
            umask $old_umask;
            return undef;
        }

        # Remove a stale socket file if (and only if) it's really a socket
        if (-e $sock_path) {
            my @st = lstat $sock_path;
            unless (@st) { carp "lstat($sock_path): $!"; umask $old_umask; return undef }
            unless (S_ISSOCK($st[2])) {
                carp "Refusing to unlink non-socket path $sock_path";
                umask $old_umask;
                return undef;
            }
            unlink $sock_path
              or do { carp "unlink($sock_path): $!"; umask $old_umask; return undef };
        }
    }

    # 4) Create the socket with CLOEXEC
    socket(my $sock_fh, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)
        or do { carp "socket(): $!"; umask $old_umask; return undef };

    # Older Perls: make sure FD_CLOEXEC is set
    unless (fcntl($sock_fh, F_SETFD, FD_CLOEXEC)) {
        carp "fcntl(FD_CLOEXEC): $!";
        close $sock_fh;
        umask $old_umask;
        return undef;
    }

    # 5) Ask kernel to pass SCM_CREDENTIALS for peer-cred checks
    unless (setsockopt($sock_fh, SOL_SOCKET, SO_PASSCRED, pack('i', 1))) {
        carp "setsockopt(SO_PASSCRED): $!";
        close $sock_fh;
        umask $old_umask;
        return undef;
    }

    # 6) Bind – works for both pathname and abstract sockets
    unless (bind($sock_fh, sockaddr_un($sock_path))) {
        carp "bind($sock_path): $!";
        close $sock_fh;
        umask $old_umask;
        return undef;
    }

    # 7) Tighten on-disk permissions **only for pathname sockets**
    unless ($abstract) {
        chmod $mode, $sock_path
          or do { carp "chmod($sock_path): $!"; close $sock_fh; umask $old_umask; return undef };

        if ($uid >= 0 || $gid >= 0) {
            chown $uid, $gid, $sock_path
              or do { carp "chown($sock_path): $!"; close $sock_fh; umask $old_umask; return undef };
        }
    }

    # 8) Start listening
    unless (listen($sock_fh, $backlog)) {
        carp "listen(): $!";
        close $sock_fh;
        umask $old_umask;
        return undef;
    }

    # 9) Bless into IO::Socket::UNIX
    bless $sock_fh, 'IO::Socket::UNIX';

    umask $old_umask;    # restore original umask
    return $sock_fh;
}
########################################################################


########################################################################
# gv_dir.pm
########################################################################
sub gv_dir::abs {
    my ($path) = @_;
    return if not defined $path;

    # NEW: leave abstract (NUL-prefixed) names untouched
    return $path if substr($path, 0, 1) eq "\0";

    return Cwd::abs_path($path);
}
########################################################################


########################################################################
# ev_socket.pm
########################################################################
sub add {
    my ($g, %args) = @_;

    # Require path
    my $path = $args{path};
    my $abstract = $args{abstract} // 0;      # <-- NEW
    $path = gv_dir::abs($path) if defined $path && !$abstract;
    unless ($path) { warn "ev_socket::create requires 'path' parameter\n"; return }

    # Require mode (still mandatory even if unused for abstract sockets)
    my $mode = $args{mode};
    unless (defined $mode) { warn "ev_socket::create requires 'mode' parameter\n"; return }

    if (   defined $g->{_watcher}
        && defined $g->{_watcher}->{ev_socket}
        && defined $g->{_watcher}->{ev_socket}->{$path})
    {
        warn "ev_socket::socket already exists.\n";
        return;
    }

    # Determine backlog, but never exceed the system max (SOMAXCONN)
    my $max_backlog = SOMAXCONN;
    my $backlog     = defined $args{backlog} ? $args{backlog} : $max_backlog;
    $backlog        = $max_backlog if $backlog > $max_backlog;

    # Create the listening socket
    my $listener = make_unix_socket::make_unix_socket(
        path     => $path,
        mode     => $mode,
        backlog  => int($backlog),
        abstract => $abstract,               # <-- NEW
    );

    unless ($listener) {
        warn "Failed to set up socket at $path; see STDERR for details\n";
        return;
    }

    my $shown = $abstract ? "(abstract:$args{path})" : $path;
    print "Listening on $shown... [$listener]\n";

    # Accept loop via AnyEvent
    $g->{_watcher}->{ev_socket}->{$path} = AnyEvent->io(
        fh   => $listener,
        poll => 'r',
        cb   => sub {
            my $client = $listener->accept or return;
            my $creds  = get_peer_cred::get_peer_cred($client);

            unless ($creds && defined $creds->{gid} && defined $creds->{pid} && defined $creds->{uid}) {
                $client->close;
                return;
            }

            use Data::Dump qw(dump); print STDERR "\n" . (dump $creds) . "\n";

            my $hdl;
            $hdl = AnyEvent::Handle->new(
                fh       => $client,
                on_error => sub { $hdl->destroy },
                on_eof   => sub { $hdl->destroy },
            );

            $hdl->push_read(line => sub {
                my ($hdl, $line) = @_;
                $hdl->push_write("woof: $line\n");
                $hdl->destroy;    # Close after single reply
            });
        }
    );
    return 1 if defined $g->{_watcher}->{ev_socket}->{$path};
    warn("Could not make ev _watcher.\n");
    return;
}
########################################################################

#----------------------------------------------------------------------#
# _ensure_secure_directory($dir)
#   Walks each component of $dir:
#     • aborts on symlinks or non-dirs
#     • creates missing components with mode 0700
#   Returns 1 on success, undef on error (after carp).
#----------------------------------------------------------------------#
sub _ensure_secure_directory {
    my ($dir) = @_;
    my @parts = File::Spec->splitdir($dir);
    my $path  = '';

    for my $p (@parts) {
        $path = $path
              ? File::Spec->catdir($path, $p)
              : ($p || '/');
        next if $path eq '/';

        if (-e $path) {
            my @st = lstat $path;
            unless (@st) {
                carp "lstat($path): $!";
                return undef;
            }
            if (S_ISLNK($st[2])) {
                carp "Component $path is a symlink — aborting";
                return undef;
            }
            unless (S_ISDIR($st[2])) {
                carp "Component $path is not a directory";
                return undef;
            }
        }
        else {
            unless (make_path($path, { mode => 0700 })) {
                carp "make_path($path): $!";
                return undef;
            }
        }
    }
    return 1;
}

1;  # End of make_unix_socket

