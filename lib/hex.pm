package hex;
use strict;
use warnings;

# encode: bytes to lowercase hex
sub encode {
    my ($bytes) = @_;
    return unless defined $bytes && length $bytes;
    # Unpack each byte to two-digit hex
    my $hex = unpack('H*', $bytes);
    return $hex;
}

# decode: hex string to bytes
sub decode {
    my ($hex) = @_;
    return unless defined $hex && length $hex;
    # Reject odd length or non-hex chars
    return unless $hex =~ /\A[0-9a-fA-F]*\z/;
    return if length($hex) % 2;
    # Pack back to binary
    my $bytes = pack('H*', $hex);
    return $bytes;
}

1;
