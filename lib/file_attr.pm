package file_attr;

use strict;
use warnings;
use File::ExtAttr ();
use Crypt::Misc   ();

use Exporter 'import';
our @EXPORT_OK = qw(get_file_attr set_file_attr del_file_attr);

#----------------------------------------------------------
sub _with_root {
    my ($code_ref) = @_;
    return $code_ref->() if $> == 0;
    if ($< == 0) { local $> = 0; return $code_ref->() }
    return $code_ref->();
}

#----------------------------------------------------------
# get_file_attr_raw($file, $attr) -> raw 
#----------------------------------------------------------
sub get_file_attr_raw {
    my ($file, $attr) = @_;
    return unless defined $file && defined $attr;
    my $val = _with_root( sub { File::ExtAttr::getfattr($file, $attr) } );
    return (defined $val && length($val)) ? $val : undef;
}

#----------------------------------------------------------
# get_file_attr($file, $attr) -> original Perl value, or undef
#----------------------------------------------------------
sub get_file_attr {
    my ($file, $attr) = @_;
    my $val = get_file_attr_raw($file, $attr) or return;

    my $decoded;
    {
        local $@;
        eval { $decoded = b58f::decode($val) };
        return unless defined $decoded && !$@;
    }
    my $a = cbor::decode($decoded);

    my $perl;
    {
        local $@;
        eval { $perl = cbor::decode($decoded) };
        return unless defined $perl && !$@;
    }

    return $perl;
}

#----------------------------------------------------------
# set_file_attr($file, $attr, $value) -> 1 on success, undef on failure
#----------------------------------------------------------
sub set_file_attr {
    my ($file, $attr, $value) = @_;
    return unless defined $file && defined $attr && defined $value && -r $file;

    my $cbor;
    {
        local $@;
        eval { $cbor = cbor::encode($value) };
        return unless defined $cbor && !$@;
    }

    my $encoded;
    {
        local $@;
        eval { $encoded = b58f::encode($cbor) };
        return unless defined $encoded && !$@;
    }

    return _with_root(sub {
        File::ExtAttr::setfattr($file, $attr, $encoded);
    }) ? 1 : undef;
}

#----------------------------------------------------------
# del_file_attr($file, $attr)
#----------------------------------------------------------
sub del_file_attr {
    my ($file, $attr) = @_;
    return unless defined $file && defined $attr && -r $file;
    return _with_root( sub { File::ExtAttr::delfattr($file, $attr) } ) ? 1 : undef;
}

1;

