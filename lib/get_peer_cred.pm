package get_peer_cred;

use strict;
use warnings;
use Carp qw(carp);
use Socket qw(SOL_SOCKET SO_PEERCRED);

our $VERSION = '0.02';

require Exporter;
our @ISA       = qw(Exporter);
our @EXPORT_OK = qw(get_peer_cred);

# ---------------------------------------------------------------------
# _sock_const($name)
# ---------------------------------------------------------------------
# Return the numeric value of a Socket constant if it exists on the
# current platform, otherwise undef.  Keeps us 100% core-only.
# ---------------------------------------------------------------------
sub _sock_const ($) {
    my ($name) = @_;
    no strict 'refs';
    return eval { Socket->$name() };
}

# ---------------------------------------------------------------------
# get_peer_cred($socket) → \%cred | undef
# ---------------------------------------------------------------------
# Return a hash-ref with keys  pid, uid, gid   describing the peer
# connected to the supplied AF_UNIX socket handle.  On failure or on an
# unsupported platform, carp and return undef.  Never dies.
# ---------------------------------------------------------------------
sub get_peer_cred {
    my ($sock) = @_;

    unless ( defined $sock && defined fileno $sock ) {
        carp 'get_peer_cred: invalid or undefined socket handle';
        return undef;
    }

    my %cred = ( pid => undef, uid => undef, gid => undef );

    # struct ucred / sockpeercred layout    (3 × 32-bit unsigned ints)
    my $fmt3 = 'I I I';
    my $need = length pack $fmt3, 0, 0, 0;

    eval {
        # ---------- Linux --------------------------------------------------
        if ( $^O eq 'linux' ) {
            my $buf = getsockopt( $sock, SOL_SOCKET, SO_PEERCRED )
              or die "SO_PEERCRED failed: $!";
            die 'buffer too short' if length($buf) < $need;
            @cred{qw(pid uid gid)} = unpack $fmt3, $buf;
            return 1;
        }

        # ---------- OpenBSD -----------------------------------------------
        if ( $^O eq 'openbsd' ) {
            my $LOCAL_PEERCRED = _sock_const('LOCAL_PEERCRED')
              // die 'LOCAL_PEERCRED not defined';
            my $buf = getsockopt( $sock, SOL_SOCKET, $LOCAL_PEERCRED )
              or die "LOCAL_PEERCRED failed: $!";
            die 'buffer too short' if length($buf) < $need;
            @cred{qw(uid gid pid)} = unpack $fmt3, $buf;  # uid,gid,pid order
            return 1;
        }

        # ---------- FreeBSD / NetBSD / DragonFly --------------------------
        if ( $^O =~ /^(?:free|net|dragonfly)bsd$/ ) {
            eval {
                require IO::Socket::UNIX::Peercred;
                @cred{qw(uid gid)} =
                  IO::Socket::UNIX::Peercred::getpeereid($sock);
                1;
            } or die 'getpeereid unavailable';
            return 1;
        }

        # ---------- macOS / Darwin ----------------------------------------
        if ( $^O eq 'darwin' ) {
            eval {
                require IO::Socket::UNIX::Peercred;
                @cred{qw(uid gid)} =
                  IO::Socket::UNIX::Peercred::getpeereid($sock);
            } or die 'getpeereid unavailable';

            # LOCAL_PEERPID gives the peer's pid if available (10.4+)
            my $SOL_LOCAL     = _sock_const('SOL_LOCAL')     // 0; # 0 on macOS
            my $LOCAL_PEERPID = _sock_const('LOCAL_PEERPID');
            if ( defined $LOCAL_PEERPID ) {
                my $buf = getsockopt( $sock, $SOL_LOCAL, $LOCAL_PEERPID );
                ( $cred{pid} ) = unpack 'I', $buf if $buf;
            }
            return 1;
        }

        # ---------- Fallback everywhere else ------------------------------
        eval {
            require IO::Socket::UNIX::Peercred;
            @cred{qw(uid gid)} =
              IO::Socket::UNIX::Peercred::getpeereid($sock);
            1;
        } or die 'no usable credential API';

        0;
    } or do {
        carp "get_peer_cred: $@";
        return undef;
    };

    return \%cred;
}

1;
__END__
