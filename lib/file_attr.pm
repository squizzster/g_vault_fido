package file_attr;
use strict;
use warnings;
use File::ExtAttr ();
use Crypt::Misc   ();
use Exporter 'import';
our @EXPORT_OK = qw(get_file_attr set_file_attr del_file_attr);
# -- privilege helper ------------------------------------------------------

# -- low-level raw fetch ----------------------------------------------------
sub get_file_attr_raw {
    my ( $file, $attr ) = @_;
    return unless $file && $attr;
    my $val = with_root::_with_root( sub { File::ExtAttr::getfattr( $file, $attr ) } );
    ( defined $val && length $val ) ? $val : undef;
}

# -- public API: get --------------------------------------------------------
sub get_file_attr {
    my ( $file, $attr ) = @_;
    my $val = get_file_attr_raw( $file, $attr ) or return;

    my $bytes = eval { b58f::decode($val) }     or return;
    my $perl  = eval { cbor::decode($bytes) }   or return;
    $perl;
}

# -- public API: set --------------------------------------------------------
sub set_file_attr {
    my ( $file, $attr, $value ) = @_;
    return unless $file && $attr && defined $value && -r $file;

    use Data::Dump qw(dump);
    print  "\n SET_FILE_ATTR [$file] => [$attr] => [" . ( dump $value) . "].\n";
    my $packed  = eval { cbor::encode($value) }   or return;
    my $encoded = eval { b58f::encode($packed) }  or return;

    with_root::_with_root( sub { File::ExtAttr::setfattr( $file, $attr, $encoded ) } ) ? 1 : undef;
}

# -- public API: delete -----------------------------------------------------
sub del_file_attr {
    my ( $file, $attr ) = @_;
    return unless $file && $attr && -r $file;
    with_root::_with_root( sub { File::ExtAttr::delfattr( $file, $attr ) } ) ? 1 : undef;
}

1;
