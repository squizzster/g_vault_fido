package read_write;
use strict;
use warnings;
use Crypt::Misc qw(read_rawfile write_rawfile);
use Carp qw(carp);

sub read {
    my ($file) = @_;
    return if not defined $file;
    my $data;
    eval { $data = read_rawfile($file) };
    if ($@) {
        carp "read_rawfile failed: [$file].";
        return undef;
    }
    return $data;
}

sub write {
    my ($file, $data) = @_;
    return if not defined $file;
    return if not defined $data;
    my $ok;
    eval { $ok = write_rawfile($file, $data) };
    if ($@) {
        carp "write_rawfile failed: [$file].";
        return undef;
    }
    return $ok;
}

1;

