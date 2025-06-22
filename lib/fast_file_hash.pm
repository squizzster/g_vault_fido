package fast_file_hash;
use strict;
use warnings;
use Fcntl qw(:DEFAULT :seek :flock O_NONBLOCK);
use Errno qw(EAGAIN);
use File::Basename qw(basename);
use Crypt::Digest::BLAKE2b_256 qw(blake2b_256_hex);
use Exporter 'import';
use Cwd qw(abs_path);

our @EXPORT_OK = qw(fast_file_hash);

# ─── Constants governing sample sizes ─────────────────────────────────────
use constant {
    MAX_SIZE_OF_FILE_TO_SLURP  =>  999 * 1024,   # Max file size to read entirely
    FIRST_CHUNK_SIZE_TO_READ   =>  250 * 1024,   # Bytes from the beginning
    LAST_CHUNK_SIZE_TO_READ    =>  250 * 1024,   # Bytes from the end
    MID_CHUNKS_TO_CHECK_TOTAL  =>  250,          # Number of middle slices
    MINIMUM_PER_OF_FILE_TO_CHK =>  10,           # % of the file (as a minimum)
};

# Blob-separator
use constant OUR_SEPARATOR  => "\0";

# Validated integer percentage for internal use
our $MINIMUM_PER_OF_FILE_TO_CHK_INT;

BEGIN {
    my $pct_raw = MINIMUM_PER_OF_FILE_TO_CHK;
    if (!defined $pct_raw || $pct_raw !~ /^-?\d+(\.\d+)?$/) {
        warn "MINIMUM_PER_OF_FILE_TO_CHK is not a valid number, defaulting to 0.";
        $MINIMUM_PER_OF_FILE_TO_CHK_INT = 0;
    } elsif ($pct_raw < 0) {
        warn "MINIMUM_PER_OF_FILE_TO_CHK ($pct_raw) is less than 0, clamping to 0.";
        $MINIMUM_PER_OF_FILE_TO_CHK_INT = 0;
    } elsif ($pct_raw > 100) {
        warn "MINIMUM_PER_OF_FILE_TO_CHK ($pct_raw) is greater than 100, clamping to 100.";
        $MINIMUM_PER_OF_FILE_TO_CHK_INT = 100;
    } else {
        $MINIMUM_PER_OF_FILE_TO_CHK_INT = int($pct_raw);
    }

    foreach my $const_name (qw(MAX_SIZE_OF_FILE_TO_SLURP FIRST_CHUNK_SIZE_TO_READ LAST_CHUNK_SIZE_TO_READ MID_CHUNKS_TO_CHECK_TOTAL)) {
        my $val = eval $const_name;
        if (!defined $val || $val < 0) {
            die "$const_name constant is not defined or is negative. Value: " . (defined $val ? $val : 'undef');
        }
    }
}

# ─── Public API ───────────────────────────────────────────────────────────
sub fast_file_hash { __fast_file_hash_core(@_) }

# ─── Core implementation ──────────────────────────────────────────────────
sub __fast_file_hash_core {
    my ( $file_raw, $cfg_ref ) = @_;
    return undef unless defined $file_raw;

    print STDERR " ====>  [$file_raw] <---\n";
    my $digest;
    eval {
        my $file = abs_path($file_raw)
          or die "Failed to resolve absolute path for '$file_raw': $!";

        my $stref = __safe_stat($file)
          or die "stat failed for '$file': $!";

        my ( $size, $mtime ) = @$stref[ 7, 9 ]; # $size is available here

        my $cfg = __merge_config($cfg_ref);

        my ( $blob, $parts ) =
          __build_blob( $file, $cfg, $stref, $size, $mtime ); # Pass $size

        die "No data selected for hashing on '$file'" unless $parts;

        $digest = blake2b_256_hex($blob)
          or die "blake2b_256_hex failed";
    };
    if ($@) {
        # warn "Error in fast_file_hash for '$file_raw': $@";
        return undef;
    }
    return $digest;
}

# ─── Config handling (Updated for _file_size) -----------------------------
sub __merge_config {
    my ($user_cfg) = @_;
    my @known_keys = qw(
        _full_path _basename _device_id _inode _link_count _owner_uid
        _group_gid _permissions _epoch_modify _file_hash _file_size
    );

    if ( ref $user_cfg eq 'HASH' && keys %$user_cfg ) {
        my %template = map { $_ => 0 } @known_keys;
        # Only accept known keys from user_cfg
        foreach my $key (keys %$user_cfg) {
            $template{$key} = $user_cfg->{$key} if exists $template{$key};
        }
        return \%template;
    }
    if ( ref $user_cfg eq 'ARRAY' && @$user_cfg ) {
        my %template = map { $_ => 0 } @known_keys;
        foreach my $key (@$user_cfg) {
            $template{$key} = 1 if exists $template{$key};
        }
        return \%template;
    }
    # Default: everything on, including _file_size
    return {
        _full_path    => 1, _basename  => 1, _device_id   => 1, _inode   => 1,
        _link_count   => 1, _owner_uid => 1, _group_gid   => 1,
        _permissions  => 1, _epoch_modify => 1, _file_hash => 1,
        _file_size    => 1, # New default
    };
}

# ─── Blob construction (Updated for _file_size) ---------------------------
sub __build_blob {
    my ( $file, $cfg, $st, $size, $mtime ) = @_; # $size is passed in
    my $sep = OUR_SEPARATOR;
    my $blob  = '#__g-voice.ai__';
    my $parts = 0;
    my $append = sub { $blob .= $_[0]; ++$parts };

    if ( $cfg->{_full_path} )      { $append->("${sep}fp:$file$sep") }
    elsif ( $cfg->{_basename} )    { $append->("${sep}bn:" . basename($file) . "$sep") }

    $append->("${sep}dev:$st->[0]$sep")      if $cfg->{_device_id};
    $append->("${sep}ino:$st->[1]$sep")      if $cfg->{_inode};
    # $st->[2] (permissions) is handled below
    $append->("${sep}nlk:$st->[3]$sep")      if $cfg->{_link_count};
    $append->("${sep}uid:$st->[4]$sep")      if $cfg->{_owner_uid};
    $append->("${sep}gid:$st->[5]$sep")      if $cfg->{_group_gid};
    # $st->[7] (size) is now handled by _file_size config option
    $append->("${sep}mod:$mtime$sep"  )      if $cfg->{_epoch_modify};

    if ( $cfg->{_permissions} ) {
        $append->( sprintf "${sep}per:%04o$sep", $st->[2] & 07777 );
    }

    # NEW: Include file size if configured
    if ( $cfg->{_file_size} ) {
        $append->("${sep}fsz:$size$sep");
    }

    if ( $cfg->{_file_hash} ) {
        my $data_part = "${sep}dat:";
        if ($size > 0) {
            my $samples = _collect_samples( $file, $size, $mtime );
            $data_part .= $samples;
        }
        $data_part .= $sep;
        $append->($data_part);
    }
    ( $blob, $parts );
}

# ─── Sample collection & Helpers (Logic from previous response) -----------
sub __read_exact {
    my ( $fh, $len ) = @_;
    return '' if $len <= 0;
    my $buf  = '';
    my $read_total = 0;
    while ( $read_total < $len ) {
        my $want  = $len - $read_total;
        my $bytes_read = sysread( $fh, my $chunk, $want );
        return undef unless defined $bytes_read;
        last if $bytes_read == 0;
        $buf  .= $chunk;
        $read_total += $bytes_read;
    }
    return $read_total == $len ? $buf : undef;
}

sub __read_at_offset {
    my ($fh, $offset, $length) = @_;
    return '' if $length <= 0;
    sysseek($fh, $offset, SEEK_SET) or return undef;
    return __read_exact($fh, $length);
}

sub __get_distributed_mid_samples {
    my ($fh, $region_start_offset, $region_length, $total_bytes_to_read, $num_chunks_const) = @_;

    return '' if $total_bytes_to_read <= 0 || $num_chunks_const <= 0 || $region_length <= 0;

    my $buf = '';
    my $bytes_remaining_to_read_total = $total_bytes_to_read;

    my $min_chunk_read_unit_for_span_calc = 1;
    my $distribution_span = $region_length - $min_chunk_read_unit_for_span_calc;
    $distribution_span = 0 if $distribution_span < 0;

    for (my $i = 0; $i < $num_chunks_const; $i++) {
        last if $bytes_remaining_to_read_total <= 0;

        my $chunk_relative_start_offset;
        if ($num_chunks_const == 1) {
            $chunk_relative_start_offset = int($distribution_span / 2);
        } else {
            my $denom = $num_chunks_const - 1;
            $chunk_relative_start_offset =
                int( ($i * $distribution_span + int($denom/2)) / $denom );
        }
        
        $chunk_relative_start_offset = 0 if $chunk_relative_start_offset < 0;
        $chunk_relative_start_offset = $distribution_span if $chunk_relative_start_offset > $distribution_span;
        
        my $file_offset = $region_start_offset + $chunk_relative_start_offset;

        my $num_remaining_conceptual_chunks = $num_chunks_const - $i;
        my $len_this_chunk = int(
            ($bytes_remaining_to_read_total + $num_remaining_conceptual_chunks - 1)
            / $num_remaining_conceptual_chunks
        );

        my $max_possible_from_this_file_offset = ($region_start_offset + $region_length) - $file_offset;
        $max_possible_from_this_file_offset = 0 if $max_possible_from_this_file_offset < 0;
        $len_this_chunk = $max_possible_from_this_file_offset if $len_this_chunk > $max_possible_from_this_file_offset;

        if ($len_this_chunk > 0) {
            my $chunk_data = __read_at_offset($fh, $file_offset, $len_this_chunk);
            defined $chunk_data or return undef;
            $buf .= $chunk_data;
            $bytes_remaining_to_read_total -= length($chunk_data);
        }
    }
    return $buf;
}

sub _collect_samples {
    my ( $file, $size, $mtime ) = @_;

    # Open the file non‐blocking (so FIFOs won't hang us) (they won't anyway as they are zero length but still, seems harmless)
    sysopen my $fh, $file, O_RDONLY | O_NONBLOCK
      or do {
        if ($! == EAGAIN) {
            warn "Nonblocking open would block on '$file', skipping content hash";
            return undef;
        }
        die "sysopen O_RDONLY|O_NONBLOCK failed for '$file': $!";
      };

    binmode $fh;

    # Shared, nonblocking flock
    unless ( flock( $fh, LOCK_SH | LOCK_NB ) ) {
        close $fh;
        die "flock failed for '$file': $!";
    }

    # Re-stat on the open handle and compare size/mtime
    my @st_fh = stat $fh;
    unless (@st_fh) {
        close $fh;
        die "stat on open FH failed for '$file': $!";
    }
    if ( $st_fh[7] != $size || $st_fh[9] != $mtime ) {
        close $fh;
        die "File '$file' changed during hashing (size/mtime mismatch)";
    }

    my $buf = '';

    if ($size <= MAX_SIZE_OF_FILE_TO_SLURP) {
        my $data = __read_at_offset($fh, 0, $size);
        defined $data or (close $fh, die "__read_at_offset (slurp) failed for '$file': $!");
        $buf = $data;
    } else {
        my $current_file_pos = 0;

        # 1. First Chunk
        my $read_len_first = $size < FIRST_CHUNK_SIZE_TO_READ ? $size : FIRST_CHUNK_SIZE_TO_READ;
        if ($read_len_first > 0) {
            my $data = __read_at_offset($fh, $current_file_pos, $read_len_first);
            defined $data or (close $fh, die "__read_at_offset (first) failed for '$file': $!");
            $buf .= $data;
            $current_file_pos += length($data);
        }

        # 2. Determine Last Chunk's actual size and the space available for middle samples
        my $remaining_file_after_first = $size - $current_file_pos;
        $remaining_file_after_first = 0 if $remaining_file_after_first < 0;

        my $ideal_len_last = LAST_CHUNK_SIZE_TO_READ;
        my $read_len_last = $ideal_len_last < $remaining_file_after_first ? $ideal_len_last : $remaining_file_after_first;
        $read_len_last = 0 if $read_len_last < 0;

        my $available_for_middle_region = $remaining_file_after_first - $read_len_last;
        $available_for_middle_region = 0 if $available_for_middle_region < 0;

        # 3. Middle Chunks (Percentage applies to middle region's length)
        my $read_len_mid_total = 0;
        if ($available_for_middle_region > 0 && MID_CHUNKS_TO_CHECK_TOTAL > 0 && $MINIMUM_PER_OF_FILE_TO_CHK_INT > 0) {
            my $bytes_to_sample_from_middle = int(
                ($available_for_middle_region * $MINIMUM_PER_OF_FILE_TO_CHK_INT + 99) / 100
            );
            $read_len_mid_total = $bytes_to_sample_from_middle;
            $read_len_mid_total = $available_for_middle_region if $read_len_mid_total > $available_for_middle_region;
            $read_len_mid_total = 0 if $read_len_mid_total < 0;
        }

        if ($read_len_mid_total > 0) {
            my $mid_region_start_offset = $current_file_pos;
            my $mid_data = __get_distributed_mid_samples(
                $fh, $mid_region_start_offset, $available_for_middle_region,
                $read_len_mid_total, MID_CHUNKS_TO_CHECK_TOTAL
            );
            defined $mid_data or (close $fh, die "__get_distributed_mid_samples failed for '$file': $!");
            $buf .= $mid_data;
        }

        # 4. Last Chunk
        if ($read_len_last > 0) {
            my $last_chunk_start_offset = $size - $read_len_last;
            my $data = __read_at_offset($fh, $last_chunk_start_offset, $read_len_last);
            defined $data or (close $fh, die "__read_at_offset (last) failed for '$file': $!");
            $buf .= $data;
        }
    }

    close $fh;
    return $buf;
}

# ─── Safe stat (Unchanged from original) ----------------------------------
sub __safe_stat {
    my @st = stat $_[0];
    return @st ? \@st : undef;
}

1;
