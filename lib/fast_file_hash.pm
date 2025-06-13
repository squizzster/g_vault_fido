package fast_file_hash;
use strict;
use warnings;
use Fcntl qw(:DEFAULT :seek :flock);    # :flock needed for LOCK_SH, LOCK_NB
use File::Basename qw(basename);
use Crypt::Digest::BLAKE2b_256 qw(blake2b_256_hex);
use Exporter 'import';
use Data::Dump qw(dump);                # As requested, not removed
use Cwd qw(abs_path);

our @EXPORT_OK = qw(fast_file_hash);

#------------------------------------------------------------------------------
# CONSTANTS
#------------------------------------------------------------------------------
use constant {
    FIRST      => 100 * 1024,  # bytes from start
    MID_TOTAL  => 100 * 1024,  # total middle sample bytes
    LAST       => 100 * 1024,  # bytes from end
    MID_CHUNKS => 100,         # number of middle chunks
    SLOP       => 100 * 1024,  # extra threshold slop
};

#------------------------------------------------------------------------------
# PUBLIC API
#------------------------------------------------------------------------------
sub fast_file_hash { return __fast_file_hash_core(@_) }

#------------------------------------------------------------------------------
# PRIVATE IMPLEMENTATION – orchestrator
#------------------------------------------------------------------------------
sub __fast_file_hash_core {
    my ( $file_raw, $cfg_ref ) = @_;
    return undef unless defined $file_raw;

    print STDERR ("Fast_file_hash [$file_raw].\n");
    my $digest;
    eval {
        my $file = abs_path($file_raw)
          or die "Failed to resolve absolute path for '$file_raw': $!";

        my $stref = __safe_stat($file)
          or die "_safe_stat failed for '$file': $!";
        my @st            = @{$stref};
        my $initial_size  = $st[7];
        my $initial_mtime = $st[9];

        my $cfg = __merge_config($cfg_ref);

        my $cfg_str = b58f::encode ( cbor::encode( $cfg ) ) ;
        ##print "\n CFG_STR [$cfg_str].\n";

        my ( $blob, $parts ) =
          __build_blob( $file, $cfg, \@st, $initial_size, $initial_mtime );

        die "No data selected for hashing on '$file'" unless $parts;
        $digest = blake2b_256_hex($blob)
          or die "blake2b_256_hex failed";
    };
    return undef if $@;
    return $digest;
}

#------------------------------------------------------------------------------
# CONFIG HANDLING
#------------------------------------------------------------------------------
sub __merge_config {
    my ($user_cfg) = @_;

    my $default_cfg = { ### these are sane for any file... 
        _full_path    => 1,        # canonical abs path; covers basename implicitly
        _basename     => 1,        # ← harmless duplication due to full-path-rule, keeps UX simple
        _device_id    => 1,        # same file restored on another fs is NOT OK !
        _inode        => 1,        # inode must match; detects “replace-in-place” tricks - any updates must use same inode
        _link_count   => 1,        # hard-link anomalies show up
        _owner_uid    => 1,        # root→non-root or vice-versa trips digest
        _group_gid    => 1,        # same for group
        _permissions  => 1,        # mode bits (suid, sgid, +x) are critical
        _epoch_modify => 1,        # mtime drift often indicates tampering    - updates would fail without modification
        _file_hash    => 1,        # sample-based BLAKE2b-256 of the contents - updates would fail without modification
    };

    ## Double check that user supplied values over-write the default, non-supplied values are default assigned.
    if (defined $user_cfg && ref($user_cfg) eq 'HASH') {
        @$default_cfg{ keys %$user_cfg } = values %$user_cfg;
    }

    return $default_cfg;
}

#------------------------------------------------------------------------------
# BLOB CONSTRUCTION
#------------------------------------------------------------------------------
sub __build_blob {
    my ( $file, $cfg_hr, $st_aref, $initial_size, $initial_mtime ) = @_;

    my $blob  = '#__g-voice.ai__';
    my $parts = 0;
    my $append = sub { $blob .= $_[0]; ++$parts };

    if ( $cfg_hr->{_full_path} ) {
        $append->("\0fn:$file\0");
    }
    elsif ( $cfg_hr->{_basename} ) {
        $append->("\0bn:" . basename($file) . "\0");
    }

    $append->("\0dev:$st_aref->[0]\0")      if $cfg_hr->{_device_id};
    $append->("\0ino:$st_aref->[1]\0")      if $cfg_hr->{_inode};
    $append->("\0nlink:$st_aref->[3]\0")    if $cfg_hr->{_link_count};
    $append->("\0mod:$st_aref->[9]\0")      if $cfg_hr->{_epoch_modify};
    $append->("\0gid:$st_aref->[5]\0")      if $cfg_hr->{_group_gid};
    $append->("\0tag:$cfg_hr->{_our_tag}\0")
      if length $cfg_hr->{_our_tag};
    $append->("\0uid:$st_aref->[4]\0")      if $cfg_hr->{_owner_uid};

    if ( $cfg_hr->{_permissions} ) {
        my $perm = sprintf "%04o", $st_aref->[2] & 07777;
        $append->("\0per:$perm\0");
    }

    if ( $cfg_hr->{_file_hash} ) {
        my $data_part = "\0dat:";
        if ( $initial_size == 0 ) {
            $data_part .= '';
        } else {
            my $samples = _collect_samples($file, $initial_size, $initial_mtime)
              or die "_collect_samples failed for '$file'";
            $data_part .= $samples;
        }
        $data_part .= "\0";
        $append->($data_part);
    }

    return ( $blob, $parts );
}

#------------------------------------------------------------------------------
# FILE SAMPLES
#------------------------------------------------------------------------------
sub _collect_samples { return __collect_samples_impl(@_) }

sub __collect_samples_impl {
    my ( $file, $initial_size, $initial_mtime ) = @_;

    sysopen my $fh, $file, O_RDONLY or return undef;
    binmode $fh;

    unless ( flock( $fh, LOCK_SH | LOCK_NB ) ) {
        close $fh;
        die "Could not acquire shared lock on '$file': $!";
    }

    my @fstat_info = stat $fh;                           # <-- changed here
    unless (@fstat_info) {
        close $fh;
        die "stat on filehandle failed for '$file': $!";
    }
    if ( $fstat_info[7] != $initial_size
      || $fstat_info[9] != $initial_mtime ) {
        close $fh;
        die "File '$file' changed during hashing process";
    }

    my $collector = '';
    if ( __should_slurp($initial_size) ) {
        sysseek( $fh, 0, SEEK_SET ) or ( close $fh and return undef );
        $collector = __read_exact( $fh, $initial_size )
          or ( close $fh and return undef );
    } else {
        $collector .= __collect_first($fh)                or ( close $fh and return undef );
        $collector .= __collect_mid( $fh, $initial_size ) or ( close $fh and return undef )
          if MID_CHUNKS > 0 && MID_TOTAL > 0;
        $collector .= __collect_last( $fh, $initial_size ) or ( close $fh and return undef );
    }

    close $fh;
    return $collector;
}

# ---------- granular helpers ----------
sub __should_slurp { my ($size) = @_; $size <= FIRST + MID_TOTAL + LAST + SLOP }

sub __read_exact {
    my ( $fh, $len ) = @_;
    return '' if $len == 0;
    my $buf;
    my $bytes = sysread( $fh, $buf, $len );
    return undef unless defined $bytes && $bytes == $len;
    return $buf;
}

sub __collect_first {
    my ($fh) = @_;
    sysseek( $fh, 0, SEEK_SET ) or return undef;
    __read_exact( $fh, FIRST );
}

sub __collect_mid {
    my ( $fh, $size ) = @_;
    my $mid_chunk = ( MID_CHUNKS && MID_TOTAL ) ? int( MID_TOTAL / MID_CHUNKS ) || 1 : 0;
    return '' unless $mid_chunk;

    my $range = $size - FIRST - LAST;
    return '' if $range <= 0;

    my $step = ( MID_CHUNKS > 1 && $range > $mid_chunk )
             ? ( $range - $mid_chunk ) / ( MID_CHUNKS - 1 )
             : 0;

    my $buf = '';
    for my $i ( 0 .. MID_CHUNKS - 1 ) {
        my $offset = MID_CHUNKS == 1
          ? int( $range / 2 ) - int( $mid_chunk / 2 )
          : int( $step * $i );
        $offset = 0 if $offset < 0;

        my $off = FIRST + $offset;
        $off = $size - LAST - $mid_chunk if $off + $mid_chunk > $size - LAST;
        $off = FIRST if $off < FIRST;
        return undef if $off < FIRST || $off + $mid_chunk > $size - LAST;

        sysseek( $fh, $off, SEEK_SET ) or return undef;
        my $chunk = __read_exact( $fh, $mid_chunk ) or return undef;
        $buf .= $chunk;
    }
    return $buf;
}

sub __collect_last {
    my ( $fh, $size ) = @_;
    my $seek = $size - LAST;
    $seek = 0 if $seek < 0;
    sysseek( $fh, $seek, SEEK_SET ) or return undef;
    __read_exact( $fh, LAST );
}

#------------------------------------------------------------------------------
# SAFE STAT
#------------------------------------------------------------------------------
sub _safe_stat { return __safe_stat(@_) }

sub __safe_stat {
    my ($file) = @_;
    my @st = stat $file;
    return undef unless @st;
    return \@st;
}

1;  # End of fast_file_hash.pm
