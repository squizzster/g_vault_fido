package fast_file_hash;

use strict;
use warnings;
use Fcntl qw(:DEFAULT :seek);
use File::Basename qw(basename);
use Crypt::Digest::BLAKE2b_256 qw(blake2b_256_hex);
use Exporter 'import';
use Data::Dump qw(dump);

# For optional logging of errors if eval catches something
# use Carp qw(carp); # Uncomment if you want to log errors from eval

our @EXPORT_OK = qw(fast_file_hash);

#------------------------------------------------------------------------------
# Constants for sampling-based content collection
#------------------------------------------------------------------------------
use constant {
    FIRST      => 100 * 1024,  # bytes from start
    MID_TOTAL  => 100 * 1024,  # total middle sample bytes
    LAST       => 100 * 1024,  # bytes from end
    MID_CHUNKS => 100,         # number of middle chunks
    SLOP       => 100 * 1024,  # extra threshold slop for deciding full read vs sample
};

#------------------------------------------------------------------------------
# _collect_samples: read or sample a file's content and return raw bytes
#------------------------------------------------------------------------------
sub _collect_samples {
    my ($file) = @_;
    my $size = -s $file;
       return undef unless defined $size;    # non-existent/inaccessible

    sysopen my $fh, $file, O_RDONLY or return undef;
    binmode $fh;

    my $threshold = FIRST + MID_TOTAL + LAST + SLOP;
    my $mid_chunk = (MID_CHUNKS > 0 && MID_TOTAL > 0)
                  ? (int(MID_TOTAL / MID_CHUNKS) || 1)
                  : 0;

    my ($buf, $bytes_read);
    my $collector = '';

    if ($size <= $threshold) {
        # small file: slurp whole thing
        $bytes_read = sysread($fh, $buf, $size);
        close $fh;
        return undef unless defined $bytes_read && $bytes_read == $size;
        $collector .= $buf;
    }
    else {
        # 1) FIRST bytes
        $bytes_read = sysread($fh, $buf, FIRST);
        return undef unless defined $bytes_read && $bytes_read == FIRST;
        $collector .= $buf;

        # 2) MID_CHUNKS samples
        if ($mid_chunk > 0) {
            my $range = $size - FIRST - LAST;
            my $step  = (MID_CHUNKS > 1 && $range > 0)
                      ? $range / (MID_CHUNKS - 1)
                      : 0;

            for my $i (0 .. MID_CHUNKS - 1) {
                my $offset_in_range;
                if (MID_CHUNKS == 1) {
                    $offset_in_range = int($range/2) - int($mid_chunk/2);
                    $offset_in_range = 0 if $offset_in_range < 0;
                } else {
                    $offset_in_range = int($step * $i);
                }

                my $off = FIRST + $offset_in_range;
                $off = $size - LAST - $mid_chunk if $off + $mid_chunk > $size - LAST;
                $off = FIRST             if $off < FIRST;

                # ensure valid
                if ($off < FIRST || $off + $mid_chunk > $size - LAST) {
                    close $fh;
                    return undef;
                }

                sysseek($fh, $off, SEEK_SET) or (close $fh, return undef);
                $bytes_read = sysread($fh, $buf, $mid_chunk);
                return undef unless defined $bytes_read && $bytes_read == $mid_chunk;
                $collector .= $buf;
            }
        }

        # 3) LAST bytes
        sysseek($fh, $size - LAST, SEEK_SET) or (close $fh, return undef);
        $bytes_read = sysread($fh, $buf, LAST);
        close $fh;
        return undef unless defined $bytes_read && $bytes_read == LAST;
        $collector .= $buf;
    }

    return $collector;
}

#------------------------------------------------------------------------------
# _safe_stat: single stat invocation, returns arrayref or undef
#------------------------------------------------------------------------------
sub _safe_stat {
    my ($file) = @_;
    my @st = stat $file;
    return undef unless @st;
    return \@st;
}

#------------------------------------------------------------------------------
# fast_file_hash: composite fingerprint using metadata and/or raw content
#------------------------------------------------------------------------------
sub fast_file_hash {
    my ($file, $cfg_ref) = @_;

    return undef unless defined $file;

    my $result_digest;
    eval {
        # stat & size
        my $stref = _safe_stat($file)
            or die "_safe_stat failed for '$file': $!";
        my @st   = @$stref;
        my $size = $st[7];

        # default config
        my %default_cfg = (
            include_full_path    => 0,
            include_basename     => 1,
            include_inode        => 0,
            include_owner_uid    => 1,
            include_group_gid    => 1,
            include_permissions  => 1,
            include_epoch_modify => 0,
            include_file_hash    => 0,
            include_our_tag      => ''
        );
        my %cfg = %default_cfg;
        if (defined $cfg_ref && ref $cfg_ref eq 'HASH') {
            @cfg{ keys %{$cfg_ref} } = values %{$cfg_ref};
        }

        # #dev only # print STDERR "\n\n" . ( dump \%cfg);

        # build blob, pepper start with g-Voice,
        my $blob = '#__g-voice.ai__';
        my $parts = 0;

        if ($cfg{include_full_path}) {
            $blob .= "\0fn:$file\0";
            $parts++;
        }
        if ($cfg{include_basename}) {
            $blob .= "\0bn:" . basename($file) . "\0";
            $parts++;
        }
        if ($cfg{include_inode}) {
            $blob .= "\0ino:$st[1]\0";
            $parts++;
        }
        if ($cfg{include_epoch_modify}) {
            $blob .= "\0mod:$st[9]\0";
            $parts++;
        }
        if ($cfg{include_group_gid}) {
            $blob .= "\0gid:$st[5]\0";
            $parts++;
        }
        if ($cfg{include_our_tag}) {
            $blob .= "\0tag:$cfg{include_our_tag}\0";
            $parts++;
        }
        if ($cfg{include_owner_uid}) {
            $blob .= "\0uid:$st[4]\0";
            $parts++;
        }
        if ($cfg{include_permissions}) {
            my $perm = sprintf "%04o", $st[2] & 07777;
            $blob .= "\0per:$perm\0";
            $parts++;
        }

        if ($cfg{include_file_hash}) {
            $blob .= "\0dat:";
            if ($size == 0) {
                $blob .= "EMPTY\0";
            } else {
                my $samples = _collect_samples($file)
                    or die "_collect_samples failed for '$file'";
                $blob .= $samples . "\0";
            }
            $parts++;
        }

        die "No data selected for hashing on '$file'" unless $parts;
        $result_digest = blake2b_256_hex($blob) or die "blake2b_256_hex failed";
    };
    return undef if $@;

    return $result_digest;
}

1;
