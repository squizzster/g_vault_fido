package fast_file_hash;

use strict;
use warnings;
use Fcntl qw(:DEFAULT :seek);
use Crypt::Digest::BLAKE2b_256 qw(blake2b_256_hex);
use Exporter 'import';
our @EXPORT_OK = qw(fast_file_hash);

#------------------------------------------------------------------------------
# OBJECTIVE:
#   Generate a robust hash of a file while minimizing I/O syscalls.
#   Always return a hex digest or undef on failure.
#
# STRATEGY:
#   • For files up to (FIRST + MID_TOTAL + LAST + SLOP) — read the entire file
#     in one go (minimal syscalls).
#   • For larger files — sample only MID_TOTAL + FIRST + LAST bytes via:
#       1) FIRST bytes from the start
#       2) MID_CHUNKS evenly spaced chunks totaling MID_TOTAL bytes in middle
#       3) LAST bytes from the end
#   • This sampling pattern maximizes detection of localized modifications
#     (e.g., hidden ELF tweaks) while keeping I/O overhead low.
#   • Explicitly validate each sysread/sysseek for exact byte counts.
#   • Accumulate directly into a single buffer, then hash once with BLAKE2b-256.
#------------------------------------------------------------------------------


use constant {
    FIRST      => 100 * 1024,    # FIRST bytes to read
    MID_TOTAL  => 100 * 1024,    # total middle sample bytes
    LAST       => 100 * 1024,    # LAST bytes to read
    MID_CHUNKS => 100,           # number of middle sample slices
    SLOP       => 100 * 1024,    # extra slop bytes to expand slurp threshold
};

sub fast_file_hash {
    my ($file) = @_;
    return undef unless defined $file;

    # Determine file size
    my $size = -s $file;
    return undef unless defined $size;

    # Open once in raw mode
    sysopen my $fh, $file, O_RDONLY or return undef;
    binmode $fh;

    # Compute parameters
    my $threshold = FIRST + MID_TOTAL + LAST + SLOP;
    my $mid_chunk = int(MID_TOTAL / MID_CHUNKS) || 1;

    my ($buf, $bytes);
    my $collector = '';

    if ($size <= $threshold) {
        # SMALL FILE: read all bytes in one go
        $bytes = sysread($fh, $buf, $size);
        close $fh;
        return undef unless defined $bytes && $bytes == $size;
        $collector .= $buf;
    }
    else {
        # LARGE FILE: three-stage sampling

        # 1) read FIRST bytes
        $bytes = sysread($fh, $buf, FIRST);
        return undef unless defined $bytes && $bytes == FIRST;
        $collector .= $buf;

        # 2) sample MID_TOTAL bytes in MID_CHUNKS slices
        my $range = $size - FIRST - LAST;
        my $step  = $range / MID_CHUNKS;
        for my $i (0 .. MID_CHUNKS - 1) {
            my $off = FIRST + int($step * $i);
            # prevent overlapping into LAST bytes
            if ($off + $mid_chunk > $size - LAST) {
                $off = $size - LAST - $mid_chunk;
            }
            sysseek($fh, $off, SEEK_SET) or return undef;
            $bytes = sysread($fh, $buf, $mid_chunk);
            return undef unless defined $bytes && $bytes == $mid_chunk;
            $collector .= $buf;
        }

        # 3) read LAST bytes
        sysseek($fh, $size - LAST, SEEK_SET) or return undef;
        $bytes = sysread($fh, $buf, LAST);
        close $fh;
        return undef unless defined $bytes && $bytes == LAST;
        $collector .= $buf;
    }

    # Hash once with hex output
    return blake2b_256_hex($collector);
}

1;
