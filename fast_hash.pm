package fast_hash;

use strict;
use warnings;
use Fcntl qw(:DEFAULT :seek);
use Crypt::Digest::BLAKE2b_256 qw(blake2b_256);
use Exporter 'import';
our @EXPORT_OK = qw(fast_hash);

use constant {
    FIRST      => 100 * 1024,    # first 100 KiB
    MID_TOTAL  => 100 * 1024,    # total middle sample
    LAST       => 100 * 1024,    # last 100 KiB
    MID_CHUNKS => 100,           # number of middle slices
    SLOP       => 100 * 1024,    # extra 100 KiB to slurp threshold
};

sub fast_hash {
    my ($file) = @_;
    return undef unless defined $file;

    my $size = -s $file;
    return undef unless defined $size;

    # open file once
    sysopen my $fh, $file, O_RDONLY or return undef;
    binmode $fh;

    my $first      = FIRST;
    my $mid_total  = MID_TOTAL;
    my $last       = LAST;
    my $chunks     = MID_CHUNKS;
    my $mid_chunk  = int($mid_total / $chunks) || 1;
    # slurp threshold = sample total + some slop to cover syscall cost
    my $threshold  = $first + $mid_total + $last + SLOP;

    my ($buf, $bytes);
    my $collector = '';

    if ($size <= $threshold) {
        # small file: read entire
        $bytes = sysread($fh, $buf, $size);
        close $fh;
        return undef unless defined $bytes && $bytes == $size;
        $collector .= $buf;
    }
    else {
        # 1) first 100 KiB
        $bytes = sysread($fh, $buf, $first);
        return undef unless defined $bytes && $bytes == $first;
        $collector .= $buf;

        # 2) middle samples
        my $range = $size - $first - $last;
        my $step  = $range / $chunks;
        for my $i (0 .. $chunks - 1) {
            my $off = $first + int($step * $i);
            # avoid overlapping last segment
            if ($off + $mid_chunk > $size - $last) {
                $off = $size - $last - $mid_chunk;
            }
            sysseek($fh, $off, SEEK_SET) or return undef;
            $bytes = sysread($fh, $buf, $mid_chunk);
            return undef unless defined $bytes && $bytes == $mid_chunk;
            $collector .= $buf;
        }

        # 3) last 100 KiB
        sysseek($fh, $size - $last, SEEK_SET) or return undef;
        $bytes = sysread($fh, $buf, $last);
        close $fh;
        return undef unless defined $bytes && $bytes == $last;
        $collector .= $buf;
    }

    # final hash
    return _hash($collector);
}

# private: wrap eval and unpack
sub _hash {
    my ($data) = @_;
    my $raw = eval { blake2b_256($data) } or return undef;
    return unpack 'H*', $raw;
}

1;

