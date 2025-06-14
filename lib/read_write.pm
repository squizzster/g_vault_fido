package read_write;
use strict;
use warnings;
use Crypt::Misc qw(read_rawfile write_rawfile);
use Carp qw(carp);

sub read  {
    my ($file) = @_; return unless $file;
    eval { Crypt::Misc::read_rawfile($file) } // ( carp "read_rawfile failed: [$file]", undef );
}

sub write {
    my ( $file, $data ) = @_; return unless $file && defined $data;
    eval { Crypt::Misc::write_rawfile( $file, $data ) } // ( carp "write_rawfile failed: [$file]", undef );
}

1;
