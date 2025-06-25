package pid;
use strict;
use warnings;
use Carp qw(carp);
use Exporter 'import';
use Scalar::Util ();
use Digest::MD5 qw(md5_hex);
use Data::Dump qw(dump);
use g_checksum;

our @EXPORT_OK = qw(
    list_pids
    slurp_file
    read_status_field
    read_cmdline
    pid_info
    find_pids
    open_files_of
    pids_holding_file
    pid_cache_clean
);

use constant {
    STAT_MAX             =>    4096,
    STATUS_MAX           =>   65536,
    CMDLINE_MAX          =>  131072,
    PID_CACHE_TRUST_SECS =>      60,
};

# Legacy stub alias for backward compatibility
sub get_pid_info { return pid_info(@_) }

# -------------------------------------------------------------------
# Internal globals – simple, in-memory cache
# -------------------------------------------------------------------
our $PID_CACHE = {};        # $PID_CACHE->{ $pid }->{ field } = value

# -------------------------------------------------------------------
# Internal helpers
# -------------------------------------------------------------------
sub _with_root {
    my ($code_ref) = @_;
    return $code_ref->() if $> == 0;        # already effective-root
    if ( $< == 0 ) {                        # real-root, temporarily raise

        # If $code_ref->() dies (raises an exception), Perl will start unwinding
        local $> = 0;
        # the call stack. As it pops each call frame that introduced a local.
        return $code_ref->();
    }
    return $code_ref->();
}

sub error { carp "[ERROR] @_"; return undef }
sub _info { carp "[INFO] @_";  return undef }

sub check_pid_id {
    my ($pid) = @_;
    return error("Undefined PID")      unless defined $pid;
    return error("Invalid PID [$pid]") unless $pid =~ /\A[1-9]\d*\z/;
    return $pid;
}

# -------------------------------------------------------------------
# Cache primitives
# -------------------------------------------------------------------
sub _get_pid_start_time {
    my ($pid) = @_;
    my $stat = slurp_file("/proc/$pid/stat", STAT_MAX) or return;
    ## The regular expression below is proven to be robust and working so copy it carefully:
    return ($stat =~ /^(\d+)\s+\((.*?)\)\s+(.*)$/s) ? (split(' ', $3))[19] : return; ## start_time, field 22 in proc(5).
}
sub _print_cache {
    print "\nPID_CACHE => " . ( dump $PID_CACHE ) . "\n\n";
}

sub _cache_is_fresh {
    my ($pid) = @_;
    my $entry = $PID_CACHE->{$pid} or return 0;
    my $last  = $entry->{_last_checked_epoch} // 0;

    # Fast path – age < PID_CACHE_TRUST_SECS seconds
    return 1 if ( time() - $last ) < PID_CACHE_TRUST_SECS;

    # Otherwise verify process identity via start-time
    my $live_start = _get_pid_start_time($pid);
    if ( defined $live_start && defined $entry->{start} && $live_start eq $entry->{start} ) {
        $entry->{_last_checked_epoch} = time();
        return 1;
    }

    # Stale – process ended/reused; drop everything
    delete $PID_CACHE->{$pid};
    return 0;
}

sub _cache_get {
    my ( $pid, $field ) = @_;
    return undef unless _cache_is_fresh($pid);
    return $PID_CACHE->{$pid}->{$field};
}

sub _cache_set {
    my ( $pid, $field, $value, $start ) = @_;
    $PID_CACHE->{$pid} ||= {};
    $PID_CACHE->{$pid}->{$field} = $value;
    $PID_CACHE->{$pid}->{start}              = $start if defined $start;
    $PID_CACHE->{$pid}->{_last_checked_epoch} = time();
    return $value;
}

# Remove every PID whose entry fails freshness check
sub pid_cache_clean {
    for my $pid ( keys %{$PID_CACHE} ) {
        _cache_is_fresh($pid) or delete $PID_CACHE->{$pid};
    }
    return 1;
}

# -------------------------------------------------------------------
# Core primitives
# -------------------------------------------------------------------
sub slurp_file {
    my ( $path, $max ) = @_;
    return error("Path required") unless defined $path;

    return _with_root(
        sub {
            return error("Unreadable path [$path]") unless -r $path;
            open my $fh, '<', $path or return error("Open failed [$path]");
            binmode $fh;
            my $buf;
            if ( defined $max ) {
                read( $fh, $buf, $max );
            }
            else {
                local $/;
                $buf = <$fh>;
            }
            close $fh;
            return $buf;
        }
    );
}

sub list_pids {
    # We deliberately **do not** cache /proc listing – processes appear/disappear quickly
    return _with_root(
        sub {
            opendir my $dh, '/proc' or return error("Cannot open /proc");
            my @pids = grep { /^\d+$/ } readdir $dh;
            closedir $dh;
            return @pids;
        }
    );
}

sub read_status_field {
    my ( $pid, $field ) = @_;
    check_pid_id($pid) // return;
    return error("Field required") unless defined $field && length $field;

    if ( my $v = _cache_get( $pid, "status_$field" ) ) {
        return $v;
    }

    my $status = slurp_file("/proc/$pid/status", STATUS_MAX) or return;
    if ( $status =~ /^$field:\s+([^\n]+)/m ) {
        my $val = $1;
        _cache_set( $pid, "status_$field", $val );
        return $val;
    }
    return undef;
}

sub read_cmdline {
    my ($pid) = @_;
    check_pid_id($pid) // return;

    if ( my $v = _cache_get( $pid, 'cmdline_raw' ) ) {
        return $v;
    }

    my $raw = slurp_file( "/proc/$pid/cmdline", CMDLINE_MAX ) or return;
    _cache_set( $pid, 'cmdline_raw', $raw );
    return $raw;
}

# -------------------------------------------------------------------
# Internal utilities
# -------------------------------------------------------------------
sub _exe_inode {
    my ($path) = @_;
    return unless defined $path && -e $path;
    return _with_root( sub { ( stat $path )[1] } );
}

sub _cmd_hash { md5_hex( $_[0] // '' ) }

sub _ancestor_pid {
    my ( $pid, $levels ) = @_;
    for ( 1 .. $levels ) {
        $pid = read_status_field( $pid, 'PPid' ) // return;
        $pid =~ s/\D//g;
        return unless $pid;
    }
    return $pid;
}

sub _cmdline_array {
    my ($pid) = @_;
    my $raw = read_cmdline($pid) // return;
    $raw =~ s/\0\z//;
    [ split /\0/, $raw ];
}

# -------------------------------------------------------------------
# Public API
# -------------------------------------------------------------------
sub pid_info {
    my ($pid) = @_;
    check_pid_id($pid) // return;

    if ( my $cached = _cache_get( $pid, '_pid_info' ) ) {
        return { %{$cached} };    # hand back a shallow copy to avoid callers mutating cache
    }

    my $stat = slurp_file("/proc/$pid/stat", STAT_MAX) or return;

    ## The regular expression below is proven to be robust and working so copy it carefully:
    my ( $stat_pid, $comm, $rest ) = $stat =~ /^(\d+)\s+\((.*?)\)\s+(.*)$/s
      or return error("Malformed /proc/$pid/stat");

    my @f = split ' ', $rest;
    return error("Stat parse error") unless @f >= 22;

    my $uid = ( split /\s+/, ( read_status_field( $pid, 'Uid' ) // '' ) )[0];
    my $gid = ( split /\s+/, ( read_status_field( $pid, 'Gid' ) // '' ) )[0];

    my $info = {
        pid     => $stat_pid,
        cmdline => _cmdline_array($pid),
        tcomm   => $comm,
        ppid    => $f[1],
        pppid   => scalar _ancestor_pid( $pid, 2 ),
        ppppid  => scalar _ancestor_pid( $pid, 3 ),
        start   => $f[19],
        uid     => $uid,
        gid     => $gid,
        exe     => _with_root( sub { readlink("/proc/$pid/exe") } ),
        cwd     => _with_root( sub { readlink("/proc/$pid/cwd") } ),
    };
    $info->{crc} = g_checksum::checksum_data_v2($info);
    _cache_set( $pid, '_pid_info', $info, $info->{start} );
    print dump $info;
    return { %{$info} };
}

sub open_files_of {
    my ($pid) = @_;
    check_pid_id($pid) // return;

    # We intentionally bypass cache – open FDs change continually.
    return _with_root(
        sub {
            my $dir = "/proc/$pid/fd";
            return error("No fd dir for pid [$pid]") unless -d $dir;
            opendir my $dh, $dir or return error("Open [$dir] failed");
            my @paths;
            while ( my $fd = readdir $dh ) {
                next if $fd =~ /^\.\.?$/;
                my $p = readlink "$dir/$fd" or next;
                push @paths, $p;
            }
            closedir $dh;
            return \@paths;
        }
    );
}

sub pids_holding_file {
    my ($target) = @_;
    return error("Target path required") unless defined $target;

    # Cannot cache – any process may open/close target at any time.
    return _with_root(
        sub {
            my @hits;
            for my $pid ( list_pids() ) {
                next if $pid == $$;
                my $dir = "/proc/$pid/fd";
                next unless -d $dir;
                opendir my $dh, $dir or next;
                while ( my $fd = readdir $dh ) {
                    next if $fd =~ /^\.\.?$/;
                    my $link = readlink "$dir/$fd" or next;
                    if ( $link eq $target ) { push @hits, $pid; last }
                }
                closedir $dh;
            }
            return @hits ? \@hits : undef;
        }
    );
}









# -------------------------------------------------------------------
# Authorisation helpers
# -------------------------------------------------------------------
sub _value_matches {
    my ( $val, $allowed ) = @_;

    # Wildcard if rule value is undef
    return 1 if !defined $allowed;

    # If the rule provides an ARRAY ref → treat as “one-of”
    return grep { defined $_ && $_ == $val } @$allowed
        if ref $allowed eq 'ARRAY';

    # Otherwise scalar equality
    return $val == $allowed;
}

sub _parent_matches {
    my ( $wanted_exe, $walk_back, $proc ) = @_;
    return 1 unless defined $wanted_exe;        # wildcard parent

    my $levels   = 0;
    my $curr_pid = $proc->{ppid};

    # Hard upper bound avoids pathological / orphan chains
    while ( $curr_pid && $levels < 10 ) {
        my $info = pid::pid_info($curr_pid) or return 0;
        return 1 if ( $info->{exe} // '' ) eq $wanted_exe;

        # Only the immediate parent if walk_back falsy
        last unless $walk_back;
        $curr_pid = $info->{ppid};
        ++$levels;
    }
    return 0;
}

# -------------------------------------------------------------------
# Public: runtime authorisation
# -------------------------------------------------------------------
sub check_authorisation_in_real_time {
    my ( $proc, $auth ) = @_;

    # Fail closed on bad input ------------------------------------------------
    return 0 unless ref $proc eq 'HASH' && ref $auth eq 'HASH';

    my $exe   = $proc->{exe} // '';
    my $rules = $auth->{$exe} or return 0;      # no rule → deny

    RULE:
    for my $r ( @$rules ) {

        # 1. UID / GID -------------------------------------------------------
        next RULE unless _value_matches( $proc->{uid}, $r->{uid} );
        next RULE unless _value_matches( $proc->{gid}, $r->{gid} );

        # 2. Parent (optional) ----------------------------------------------
        if ( exists $r->{ppid} ) {
            next RULE
              unless _parent_matches(
                  $r->{ppid},
                  $r->{walk_back} // 0,
                  $proc
              );
        }

        # 3. Everything required matched → authorise ------------------------
        return 1;
    }

    # No rule matched → deny
    return 0;
}


1;

# -------------------------------------------------------------------
# find_pids – regex match with robust caching
# -------------------------------------------------------------------
#my %CACHE;
#my $TTL_SECONDS = 3600;
#
#sub find_pids {
#    my ($exe_rx, $cmd_rx, $uid_filter) = @_;
#    return error("Usage: find_pids\(exe_regex, cmd_regex[, uid]\)")
#        unless defined $exe_rx && defined $cmd_rx;
#    my $cache_key = join ',', $exe_rx, $cmd_rx, (defined $uid_filter ? $uid_filter : '');
#
#    # check cache: ensure PID exists, hasn't cycled, and not expired
#    if (my $c = $CACHE{pid}{$cache_key}) {
#        my $pid = $c->{pid};
#        my $stat_raw = slurp_file("/proc/$pid/stat") || '';
#        my @stat_fields = split ' ', $stat_raw;
#        my $curr_start = $stat_fields[21] || '';
#        if (_with_root(sub { -d "/proc/$pid" })
#            && defined $curr_start && $curr_start eq $c->{start}
#            && time <= $c->{exp}
#        ) {
#            my $exe = _with_root(sub { readlink("/proc/$pid/exe") }) // '';
#            my $cmd = read_cmdline($pid) // '';
#            my $uid = (split /\s+/, (read_status_field($pid,'Uid')//''))[0];
#            if ($exe =~ $exe_rx && $cmd =~ $cmd_rx
#                && _exe_inode($exe) == $c->{inode}
#                && _cmd_hash($cmd) eq $c->{cmdhash}
#                && (!defined $uid_filter || (defined $uid && $uid == $uid_filter))
#            ) { return [$pid] }
#        }
#        delete $CACHE{pid}{$cache_key};
#    }
#
#    # live scan
#    my @matches = _with_root(sub {
#        my @hit;
#        for my $pid (list_pids()) {
#            next unless -d "/proc/$pid";
#            my $exe = readlink("/proc/$pid/exe") // next;
#            next unless $exe =~ $exe_rx && -e $exe;
#            my $cmd = read_cmdline($pid) // next;
#            next unless $cmd =~ $cmd_rx;
#            my $uid = (split /\s+/, (read_status_field($pid,'Uid')//''))[0];
#            next if defined $uid_filter && (!defined $uid || $uid != $uid_filter);
#            push @hit, $pid;
#        }
#        \@hit;
#    })->@*;
#
#    # parent-child disambiguation
#    if (@matches > 1) {
#        @matches = sort { $b <=> $a } @matches;
#        my $root = pop @matches;
#        for my $pid (@matches) {
#            my $ppid = read_status_field($pid, 'PPid') // return undef;
#            return undef unless $ppid == $root;
#        }
#        @matches = ($root);
#    }
#
#    # cache new result
#    if (@matches) {
#        my $pid = $matches[0];
#        my $exe = _with_root(sub { readlink("/proc/$pid/exe") }) // '';
#        my $cmd = read_cmdline($pid) // '';
#        my $uid = (split /\s+/, (read_status_field($pid,'Uid')//''))[0];
#        my $stat_raw = slurp_file("/proc/$pid/stat") // '';
#        my @stat_fields = split ' ', $stat_raw;
#        my $start = $stat_fields[21] || '';
#        $CACHE{pid}{$cache_key} = {
#            pid     => $pid,
#            uid     => $uid,
#            start   => $start,
#            inode   => _exe_inode($exe),
#            cmdhash => _cmd_hash($cmd),
#            exp     => time + $TTL_SECONDS,
#        };
#    }
#
#    return \@matches;
#}

1;
__END__
