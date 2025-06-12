package get_shared_key;
use strict;
use warnings;
use Exporter 'import';
use Time::HiRes qw(time);        # high-resolution epoch
use Digest::SHA qw(sha256);      # 256-bit hash

our $VERSION   = '1.000';

#----------------------------------------------------------------------
# get_shared_key ( $drift [, $epoch ] )
# %
# % $drift : positive integer, maximum permitted skew in *either*
# %          direction between two hosts (seconds)
# % $epoch : optional override for testing
# %
# % RETURNS : 64-char hex string (256-bit key)
#----------------------------------------------------------------------

sub get_shared_key {
    my ($drift, $epoch) = @_;

    die "drift must be a positive integer\n"
        unless defined $drift && $drift =~ /^\d+$/ && $drift > 0;

    $epoch //= time();                       # default: current UTC epoch

    my $bucket_size = 2 * $drift;            # widen bucket → ±drift safety
    my $bucket      = int( ($epoch + $drift) / $bucket_size );

    return unpack 'H*', sha256( pack 'Q>', $bucket );
}

# server-side verification, no secret needed
sub verify_shared_key {
    my ($drift, $candidate_hex, $now) = @_;
    for my $offset (-1, 0, 1) {          # search neighbour buckets
        my $epoch = ($now // time()) + $offset * (2 * $drift);
        my $expected = get_shared_key($drift, $epoch);
        return 1 if lc $expected eq lc $candidate_hex;
    }
    return 0;
}
1;
__END__
