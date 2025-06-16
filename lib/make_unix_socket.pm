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
sub make_unix_socket {
    my (%opt)     = @_;
    my $sock_path = $opt{path};
    my $backlog   = exists $opt{backlog} ? $opt{backlog} : SOMAXCONN;
    my $mode      = exists $opt{mode}    ? $opt{mode}    : 0600;
    my $uid       = exists $opt{uid}     ? $opt{uid}     : -1;
    my $gid       = exists $opt{gid}     ? $opt{gid}     : -1;

    # Save & tighten umask during the sensitive window
    my $old_umask = umask();
    umask 077;

    # 1) Path sanity
    unless (defined $sock_path && length $sock_path) {
        carp "Socket path is required";
        umask $old_umask;
        return undef;
    }
    if (length($sock_path) >= 101) {             # 108 incl. NUL, slack for safety
        carp "Socket path too long for sockaddr_un (max ≈ 100 bytes)";
        umask $old_umask;
        return undef;
    }

    # 2) Ensure directory tree is secure
    unless (_ensure_secure_directory(dirname($sock_path))) {
        umask $old_umask;
        return undef;
    }

    # 3) Remove a stale socket file if (and only if) it's really a socket
    if (-e $sock_path) {
        my @st = lstat $sock_path;
        unless (@st) {
            carp "lstat($sock_path): $!";
            umask $old_umask;
            return undef;
        }
        unless (S_ISSOCK($st[2])) {
            carp "Refusing to unlink non-socket path $sock_path";
            umask $old_umask;
            return undef;
        }
        unless (unlink $sock_path) {
            carp "unlink($sock_path): $!";
            umask $old_umask;
            return undef;
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

    # 6) Bind to filesystem path
    unless (bind($sock_fh, sockaddr_un($sock_path))) {
        carp "bind($sock_path): $!";
        close $sock_fh;
        umask $old_umask;
        return undef;
    }

    # 7) Tighten permissions & ownership immediately
    unless (chmod $mode, $sock_path) {
        carp "chmod($sock_path): $!";
        close $sock_fh;
        umask $old_umask;
        return undef;
    }
    if ($uid >= 0 || $gid >= 0) {
        unless (chown $uid, $gid, $sock_path) {
            carp "chown($sock_path): $!";
            close $sock_fh;
            umask $old_umask;
            return undef;
        }
    }

    # 8) Start listening
    unless (listen($sock_fh, $backlog)) {
        carp "listen(): $!";
        close $sock_fh;
        umask $old_umask;
        return undef;
    }

    # 9) Bless into IO::Socket::UNIX so OO methods (accept, peername…) work
    bless $sock_fh, 'IO::Socket::UNIX';

    umask $old_umask;        # restore original umask
    return $sock_fh;
}

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

