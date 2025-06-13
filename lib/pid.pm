# Purpose: Robust, stackable helpers for /proc process inspection
package pid;
use strict;
use warnings;
use Carp      qw(carp croak);
use Exporter  'import';
use Scalar::Util qw(looks_like_number);
use Digest::MD5 qw(md5_hex);

our @EXPORT_OK = qw(
    _with_root
    list_pids
    slurp_file
    read_status_field
    read_cmdline
    pid_info
    find_pids
    open_files_of
    pids_holding_file
);

# -------------------------------------------------------------------
#  _with_root { ... } – run coderef with euid == 0 if possible
# -------------------------------------------------------------------
sub _with_root {
    my ($code_ref) = @_;
    return $code_ref->() if $> == 0;           # already euid root
    if ($< == 0) { local $> = 0; return $code_ref->() }  # real UID root
    return $code_ref->();                      # non-root – best effort
}

# -------------------------------------------------------------------
#  list_pids() – numeric PIDs currently in /proc
# -------------------------------------------------------------------
sub list_pids {
    opendir my $dh, '/proc' or croak 'Cannot open /proc';
    my @pids = grep { /^\d+$/ } readdir $dh;
    closedir $dh;
    return @pids;
}

# -------------------------------------------------------------------
#  slurp_file( $path [, $max_bytes] )
# -------------------------------------------------------------------
sub slurp_file {
    my ($path, $max) = @_;
    return unless -r $path;

    open my $fh, '<', $path or return;
    binmode $fh;               # good practice for arbitrary files

    my $buf;
    if (defined $max) {
        # read up to $max bytes into $buf
        read $fh, $buf, $max;
    }
    else {
        # slurp whole file
        local $/;
        $buf = <$fh>;
    }

    close $fh;
    return $buf;
}
# -------------------------------------------------------------------
#  read_status_field( $pid, $field ) ⇒ scalar | undef
# -------------------------------------------------------------------
sub read_status_field {
    my ($pid, $field) = @_;
    my $status = slurp_file("/proc/$pid/status") or return;
    $status =~ /^$field:\s+([^\n]+)/m ? $1 : undef;
}

# -------------------------------------------------------------------
#  read_cmdline( $pid ) ⇒ raw NUL-delimited cmdline | undef
# -------------------------------------------------------------------
sub read_cmdline {
    my ($pid) = @_;
    slurp_file("/proc/$pid/cmdline", 4096);
}

sub ancestor {
    my ($start_pid, $levels) = @_;
    my $pid = $start_pid;
    for (1..$levels) {
        # read the PPid of the current pid
        my $raw = read_status_field($pid, 'PPid') // return;
        ($pid) = $raw =~ /(\d+)/;    # grab the number
        return unless $pid;
    }
    return $pid;
}

sub pid_info {
    my ($pid) = @_;
    return unless looks_like_number($pid) && -d "/proc/$pid";

    my $stat = slurp_file("/proc/$pid/stat") or return;
    my @parts = grep { defined } ($stat =~ /\(([^)]*)\)|([^\s]+)/g);

    my %info = (
      pid    => $pid,
      tcomm  => $parts[1],
      ppid   => $parts[3],
      pppid  => ancestor($pid, 2),
      ppppid => ancestor($pid, 3),
      start  => $parts[21],
      uid    => (split /\s+/, (read_status_field($pid,'Uid') // ''))[0],
      gid    => (split /\s+/, (read_status_field($pid,'Gid') // ''))[0],
      exe    => readlink "/proc/$pid/exe",
      cwd    => readlink "/proc/$pid/cwd",
    );
    return \%info;
}



# -------------------------------------------------------------------
#  pid_info( $pid ) ⇒ HASHREF | undef
# -------------------------------------------------------------------
#sub pid_info {
#    my ($pid) = @_;
#    return unless looks_like_number($pid) && -d "/proc/$pid";
#
#    my $stat = slurp_file("/proc/$pid/stat") or return;
#    my @parts = ( $stat =~ /\(([^)]*)\)|([^\s]+)/g );
#    @parts = grep { defined } @parts;
#
#    my $ppid = $parts[3];  # parent's PID
#    my $pppid = do {
#        # read the PPid: line from the parent's /proc/<ppid>/status
#        my $raw = read_status_field($ppid, 'PPid') // '';
#        (split /\s+/, $raw)[0]     # grab the first number
#    };
#
#    my %info = (
#        pid   => $pid,
#        tcomm => $parts[1],
#        ppid  => $ppid,
#        pppid => $pppid || undef,   # undef if the parent has vanished
#        start => $parts[21],
#        uid   => (split /\s+/, (read_status_field($pid,'Uid') // ''))[0],
#        gid   => (split /\s+/, (read_status_field($pid,'Gid') // ''))[0],
#        exe   => readlink "/proc/$pid/exe",
#        cwd   => readlink "/proc/$pid/cwd",
#    );
#    return \%info;
#}

#sub _old_pid_info {
#    my ($pid) = @_;
#    return unless looks_like_number($pid) && -d "/proc/$pid";
#
#    my $stat = slurp_file("/proc/$pid/stat") or return;
#    my @parts = ( $stat =~ /\(([^)]*)\)|([^\s]+)/g );
#    @parts    = grep { defined } @parts;
#
#    my %info = (
#        pid   => $pid,
#        tcomm => $parts[1],
#        ppid  => $parts[3],
#        pppid => ??
#        start => $parts[21],
#        uid   => (split /\s+/, (read_status_field($pid,'Uid') // ''))[0],
#        gid   => (split /\s+/, (read_status_field($pid,'Gid') // ''))[0],
#        exe   => readlink "/proc/$pid/exe",
#        cwd   => readlink "/proc/$pid/cwd",
#    );
#    return \%info;
#}

# -------------------------------------------------------------------
#  open_files_of( $pid ) ⇒ ARRAYREF | undef
# -------------------------------------------------------------------
sub open_files_of {
    my ($pid) = @_;
    return unless -d "/proc/$pid/fd";
    opendir my $fdh, "/proc/$pid/fd" or return;
    my @paths;
    while (my $fd = readdir $fdh) {
        next if $fd =~ /^\.\.?$/;
        my $p = readlink "/proc/$pid/fd/$fd" or next;
        push @paths, $p;
    }
    closedir $fdh;
    return \@paths;
}

# -------------------------------------------------------------------
#  pids_holding_file( $path ) ⇒ HASHREF | undef
# -------------------------------------------------------------------
sub pids_holding_file {
    my ($target) = @_;
    croak 'Need target path' unless defined $target;

    return _with_root(
        sub {
            my @pids;

            for my $pid ( sort { $b <=> $a } list_pids() ) {
                next if $pid == $$;    # skip ourselves

                my $fd_dir = "/proc/$pid/fd";
                my $fdh;
                opendir $fdh, $fd_dir
                  or next;             # skip if it vanished/unreadable

                while ( defined( my $fd = readdir $fdh ) ) {
                    next if $fd eq '.' || $fd eq '..';

                    my $path = "$fd_dir/$fd";
                    my $link = readlink $path
                      or next;            # not a symlink or unreadable

                    if ( $link eq $target ) {
                        push @pids, $pid;
                        last;             # go to next PID once we’ve found one
                    }
                }

                closedir $fdh;
            }

            return @pids ? \@pids : undef;
        }
    );
}

sub __hash_pids_holding_file {
    my ($target) = @_;
    croak 'Need target path' unless defined $target;

    return _with_root(sub {
        my %hit;
        for my $pid (sort { $b <=> $a } list_pids()) {
            next if $pid == $$;

            my $fd_dir = "/proc/$pid/fd";
            my $fdh;
            opendir $fdh, $fd_dir
                or next;        # skip if it vanished or isn’t readable

            while (defined(my $fd = readdir $fdh)) {
                next if $fd =~ /^\.\.?$/;
                my $link = readlink("$fd_dir/$fd") or next;
                if ($link eq $target) {
                    $hit{$pid} = $link;
                    last;
                }
            }

            closedir $fdh;
        }
        return %hit ? \%hit : undef;
    });
}

# -------------------------------------------------------------------
#  find_pids( $exe_rx, $cmd_rx [, $uid] ) ⇒ ARRAYREF (possibly empty)
#  – robust cache with UID + start-time + exe inode + cmd hash + TTL
# -------------------------------------------------------------------
my %CACHE;
my $TTL_SECONDS = 3600;

sub _exe_inode {
    my ($path) = @_;
    return unless defined $path && -e $path;
    return (stat $path)[1];          # inode number
}

sub _cmd_hash {
    my ($cmdline) = @_;
    return md5_hex($cmdline // '');
}

sub find_pids {
    my ($exe_rx, $cmd_rx, $uid_wanted) = @_;
    croak 'Usage: find_pids($exe_regex,$cmd_regex[, $uid])'
        unless defined $exe_rx && defined $cmd_rx;

    my $key = join ',', $exe_rx, $cmd_rx, (defined $uid_wanted ? $uid_wanted : '');

    # 1) Fast-path: validate cached entry
    if (my $c = $CACHE{pid}{$key}) {
        my $pid = $c->{pid};
        if (-d "/proc/$pid") {
            my $uid   = (split /\s+/, (read_status_field($pid,'Uid')//''))[0];
            my $stat  = slurp_file("/proc/$pid/stat") // '';
            my @p     = ($stat =~ /\(([^)]*)\)|([^\s]+)/g); @p = grep { defined } @p;
            my $start = $p[21] // '';
            my $exe   = readlink "/proc/$pid/exe";
            my $cmd   = read_cmdline($pid) // '';

            if (     defined $uid   && $uid   eq $c->{uid}
                &&  defined $start && $start eq $c->{start}
                &&  defined $exe   && _exe_inode($exe) == $c->{inode}
                &&  $exe =~ $exe_rx
                &&  $cmd =~ $cmd_rx
                &&  _cmd_hash($cmd) eq $c->{cmdhash}
                &&  time <= $c->{exp} )
            {
                return [ $pid ];             # cache hit is sound
            }
        }
        delete $CACHE{pid}{$key};             # stale
    }

    # 2) Live scan of /proc
    my @hits;
    for my $pid (list_pids()) {
        next unless -d "/proc/$pid";

        my $exe = readlink("/proc/$pid/exe") // next;
        next unless $exe =~ $exe_rx && -e $exe;

        my $cmd = read_cmdline($pid) // next;
        next unless $cmd =~ $cmd_rx;

        my $uid = (split /\s+/, (read_status_field($pid,'Uid')//''))[0];
        next if defined $uid_wanted && (!defined $uid || $uid != $uid_wanted);

        push @hits, $pid;
    }

    # 3) Parent/child disambiguation (linear chain heuristic)
    if (@hits > 1) {
        @hits  = sort { $b <=> $a } @hits;    # newest … oldest
        my $root = pop @hits;
        for my $pid (@hits) {
            my $pp = (split /\s+/, (read_status_field($pid,'PPid')//''))[0];
            return [] unless defined $pp && $pp == $root;
        }
        @hits = ($root);
    }

    # 4) Cache and return
    if (@hits) {
        my $pid   = $hits[0];
        my $uid   = (split /\s+/, (read_status_field($pid,'Uid')//''))[0];
        my $stat  = slurp_file("/proc/$pid/stat") // '';
        my @p     = ($stat =~ /\(([^)]*)\)|([^\s]+)/g); @p = grep { defined } @p;
        my $start = $p[21] // '';
        my $exe   = readlink "/proc/$pid/exe";
        my $cmd   = read_cmdline($pid) // '';

        $CACHE{pid}{$key} = {
            pid     => $pid,
            uid     => $uid,
            start   => $start,
            inode   => _exe_inode($exe),
            cmdhash => _cmd_hash($cmd),
            exp     => time + $TTL_SECONDS,
        };
    }

    return \@hits;
}

1;  # End of PID::Lego

