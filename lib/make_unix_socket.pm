package make_unix_socket;

use strict;
use warnings;

use Socket    qw(AF_UNIX SOCK_STREAM SOCK_CLOEXEC SOMAXCONN sockaddr_un SOL_SOCKET SO_PASSCRED);
use Fcntl     qw(:mode F_SETFD FD_CLOEXEC);
use File::Basename qw(dirname);
use File::Path     qw(make_path);
use File::Spec     qw(catdir splitdir);
use Carp       qw(carp);

#----------------------------------------------------------------------#
# make_unix_socket(%opts)
#   Creates a hardened, file-backed AF_UNIX listening socket.
#   On success returns the socket handle; on any failure carp()s
#   and returns undef.  Never dies or exits.
#
# Options:
#   path    => '/run/myapp/app.sock'   # mandatory
#   backlog => SOMAXCONN               # optional, default SOMAXCONN
#   mode    => 0600                    # optional, default 0600
#   uid     => $>,                     # optional, default -1 (no chown)
#   gid     => $(                      # optional, default -1 (no chown)
#----------------------------------------------------------------------#
sub make_unix_socket {
    my (%opt)     = @_;
    my $sock_path = $opt{path};
    my $backlog   = exists $opt{backlog} ? $opt{backlog} : SOMAXCONN;
    my $mode      = exists $opt{mode}    ? $opt{mode}    : 0600;
    my $uid       = exists $opt{uid}     ? $opt{uid}     : -1;
    my $gid       = exists $opt{gid}     ? $opt{gid}     : -1;

    # Save & reset umask for the sensitive bind/creation window
    my $old_umask = umask();
    umask 077;

    # 1) Path sanity checks
    unless (defined $sock_path && length $sock_path) {
        carp "Socket path is required";
        umask $old_umask;
        return undef;
    }
    if (length($sock_path) >= 104) {
        carp "Socket path too long for sockaddr_un (max ≈ 103 bytes)";
        umask $old_umask;
        return undef;
    }

    # 2) Ensure directory tree is secure (no symlinks, perms 0700)
    unless (_ensure_secure_directory(dirname($sock_path))) {
        umask $old_umask;
        return undef;
    }

    # 3) Remove a stale socket file only if it really is a socket
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

    # 4) Create socket (with CLOEXEC), set FD_CLOEXEC for older Perls
    socket(my $sock, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)
        or do { carp "socket(): $!"; umask $old_umask; return undef };
    unless (fcntl($sock, F_SETFD, FD_CLOEXEC)) {
        carp "fcntl(FD_CLOEXEC): $!";
        close $sock;
        umask $old_umask;
        return undef;
    }

    # 5) Enable credential passing for ACL checks
    unless (setsockopt($sock, SOL_SOCKET, SO_PASSCRED, pack('i',1))) {
        carp "setsockopt(SO_PASSCRED): $!";
        close $sock;
        umask $old_umask;
        return undef;
    }

    # 6) Bind to the filesystem path
    unless (bind($sock, sockaddr_un($sock_path))) {
        carp "bind($sock_path): $!";
        close $sock;
        umask $old_umask;
        return undef;
    }

    # 7) Immediately tighten permissions & ownership
    unless (chmod $mode, $sock_path) {
        carp "chmod($sock_path): $!";
        close $sock;
        umask $old_umask;
        return undef;
    }
    if ($uid >= 0 || $gid >= 0) {
        unless (chown $uid, $gid, $sock_path) {
            carp "chown($sock_path): $!";
            close $sock;
            umask $old_umask;
            return undef;
        }
    }

    # 8) Begin listening
    unless (listen($sock, $backlog)) {
        carp "listen(): $!";
        close $sock;
        umask $old_umask;
        return undef;
    }

    # Restore original umask now that socket is ready
    umask $old_umask;
    return $sock;
}

#----------------------------------------------------------------------#
# _ensure_secure_directory($dir)
#   Walks each component of $dir, aborting on symlinks or non-dirs,
#   creating missing components with mode 0700.  Carp+undef on error,
#   returns 1 on success.
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

1;

