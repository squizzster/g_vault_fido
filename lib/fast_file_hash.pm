package fast_file_hash;
use strict;
use warnings;
use Fcntl qw(:DEFAULT :seek :flock);
use File::Basename qw(basename);
use Crypt::Digest::BLAKE2b_256 qw(blake2b_256_hex);
use Exporter 'import';
use Cwd qw(abs_path);
our @EXPORT_OK = qw(fast_file_hash);

# ─── Constants governing sample sizes ─────────────────────────────────────
use constant {
    FIRST      => 100 * 1024,   # first 100 KiB
    MID_TOTAL  => 100 * 1024,   # total taken from the middle
    LAST       => 100 * 1024,   # last 100 KiB
    MID_CHUNKS => 100,          # number of middle slices
    SLOP       => 100 * 1024,   # threshold for whole-file hash
};
# Blob-separator (correct spelling); keep old name as alias for callers
use constant OUR_SEPARATOR  => "\0";
use constant OUR_SEPERATOR  => OUR_SEPARATOR;   # legacy alias for any callers

# ─── Public API ───────────────────────────────────────────────────────────
sub fast_file_hash { __fast_file_hash_core(@_) }

# ─── Core implementation ──────────────────────────────────────────────────
sub __fast_file_hash_core {
    my ( $file_raw, $cfg_ref ) = @_;
    return undef unless defined $file_raw;

    my $digest;
    eval {
        my $file = abs_path($file_raw)
          or die "Failed to resolve absolute path for '$file_raw': $!";

        my $stref = __safe_stat($file)
          or die "stat failed for '$file': $!";

        my ( $size, $mtime ) = @$stref[ 7, 9 ];

        my $cfg = __merge_config($cfg_ref);

        my ( $blob, $parts ) =
          __build_blob( $file, $cfg, $stref, $size, $mtime );

        die "No data selected for hashing on '$file'" unless $parts;

        $digest = blake2b_256_hex($blob)
          or die "blake2b_256_hex failed";
    };
    $@ ? undef : $digest;
}

# ─── Config handling ------------------------------------------------------
sub __merge_config {
    my ($user_cfg) = @_;

    # explicit override **only** if it's a non-empty hashref
    if ( ref $user_cfg eq 'HASH' && keys %$user_cfg ) {
        my %template = map { $_ => 0 } qw(
            _full_path _basename _device_id _inode _link_count _owner_uid
            _group_gid _permissions _epoch_modify _file_hash
        );
        @template{ keys %$user_cfg } = values %$user_cfg;
        return \%template;
    }

    # array-style override still honoured
    if ( ref $user_cfg eq 'ARRAY' && @$user_cfg ) {
        my %template = map { $_ => 0 } qw(
            _full_path _basename _device_id _inode _link_count _owner_uid
            _group_gid _permissions _epoch_modify _file_hash
        );
        @template{@$user_cfg} = (1) x @$user_cfg;
        return \%template;
    }

    # default: everything on
    {
        _full_path    => 1, _basename  => 1, _device_id   => 1, _inode   => 1,
        _link_count   => 1, _owner_uid => 1, _group_gid   => 1,
        _permissions  => 1, _epoch_modify => 1, _file_hash => 1,
    }
}

# ─── Blob construction ----------------------------------------------------
sub __build_blob {
    my ( $file, $cfg, $st, $size, $mtime ) = @_;

    my $sep = OUR_SEPARATOR;
    my $blob  = '#__g-voice.ai__';
    my $parts = 0;

    my $append = sub { $blob .= $_[0]; ++$parts };

    if ( $cfg->{_full_path} )      { $append->("${sep}fp:$file$sep") }
    elsif ( $cfg->{_basename} )    { $append->("${sep}bn:" . basename($file) . "$sep") }

    $append->("${sep}dev:$st->[0]$sep")      if $cfg->{_device_id};
    $append->("${sep}ino:$st->[1]$sep")      if $cfg->{_inode};
                  #           [2]            # is done below...
    $append->("${sep}nlk:$st->[3]$sep")      if $cfg->{_link_count};
    $append->("${sep}uid:$st->[4]$sep")      if $cfg->{_owner_uid};
    $append->("${sep}gid:$st->[5]$sep")      if $cfg->{_group_gid};
    $append->("${sep}mod:$mtime$sep"  )      if $cfg->{_epoch_modify};

    if ( $cfg->{_permissions} ) {
        $append->( sprintf "${sep}per:%04o$sep", $st->[2] & 07777 );
    }

    if ( $cfg->{_file_hash} ) {
        my $data_part = "${sep}dat:";
        if ($size) {
            my $samples = _collect_samples( $file, $size, $mtime )
              or die "_collect_samples failed for '$file'";
            $data_part .= $samples;
        }
        $data_part .= $sep;
        $append->($data_part);
    }

    ( $blob, $parts );
}

# ─── Sample collection ----------------------------------------------------
sub _collect_samples { __collect_samples_impl(@_) }

sub __collect_samples_impl {
    my ( $file, $size, $mtime ) = @_;

    sysopen my $fh, $file, O_RDONLY or return undef;
    binmode $fh;

    unless ( flock( $fh, LOCK_SH | LOCK_NB ) ) { close $fh; return undef }

    my @st = stat $fh or ( close $fh, return undef );
    if ( $st[7] != $size || $st[9] != $mtime ) {
        close $fh; die "File '$file' changed during hashing";
    }

    my $buf = '';
    if ( __should_slurp($size) ) {
        sysseek( $fh, 0, SEEK_SET )     or ( close $fh, return undef );
        $buf .= __read_exact( $fh, $size ) or ( close $fh, return undef );
    }
    else {
        $buf .= __collect_first($fh)                  or ( close $fh, return undef );
        $buf .= __collect_mid( $fh, $size )           or ( close $fh, return undef ) if MID_CHUNKS && MID_TOTAL;
        $buf .= __collect_last( $fh, $size )          or ( close $fh, return undef );
    }
    close $fh; $buf;
}

# granular helpers
sub __should_slurp { $_[0] <= FIRST + MID_TOTAL + LAST + SLOP }

sub __read_exact {
    my ( $fh, $len ) = @_;
    return '' unless $len;

    my $buf  = '';
    my $read = 0;
    while ( $read < $len ) {
        my $want  = $len - $read;
        my $bytes = sysread( $fh, my $chunk, $want );
        return undef          unless defined $bytes;   # hard error
        last                    if     $bytes == 0;    # EOF
        $buf  .= $chunk;
        $read += $bytes;
    }
    return $read == $len ? $buf : undef;
}

sub __collect_first { sysseek( $_[0], 0, SEEK_SET ) && __read_exact( $_[0], FIRST ) }

sub __collect_mid {
    my ( $fh, $size ) = @_;
    my $mid_chunk = MID_CHUNKS ? int( MID_TOTAL / MID_CHUNKS ) || 1 : 0;
    return '' unless $mid_chunk;

    my $range = $size - FIRST - LAST; return '' if $range <= 0;

    # Use floating-point to avoid a zero-step when $range ≈ $mid_chunk
    my $step = 0;
    if ( MID_CHUNKS > 1 && $range > $mid_chunk ) {
        $step = ( $range - $mid_chunk ) / ( MID_CHUNKS - 1 );
    }

    my $buf = '';
    for my $i ( 0 .. MID_CHUNKS - 1 ) {
        my $offset = MID_CHUNKS == 1
                   ? int( $range / 2 ) - int( $mid_chunk / 2 )
                   : int( $step * $i + 0.5 );   # round — avoids duplicates

        $offset = 0 if $offset < 0;

        my $off = FIRST + $offset;
        $off = $size - LAST - $mid_chunk if $off + $mid_chunk > $size - LAST;
        $off = FIRST if $off < FIRST;

        return undef if $off < FIRST || $off + $mid_chunk > $size - LAST;

        sysseek( $fh, $off, SEEK_SET ) or return undef;
        $buf .= __read_exact( $fh, $mid_chunk ) or return undef;
    }
    $buf;
}

sub __collect_last {
    my ( $fh, $size ) = @_;
    my $seek = $size - LAST; $seek = 0 if $seek < 0;
    sysseek( $fh, $seek, SEEK_SET ) && __read_exact( $fh, LAST );
}

# ─── Safe stat ------------------------------------------------------------
sub __safe_stat { my @st = stat $_[0]; @st ? \@st : undef }

1;

