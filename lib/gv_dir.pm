package gv_dir;
use strict;
use warnings;

use File::Basename ();
use Cwd            ();


sub gv_dir::abs_path {
    my ($path) = @_;
    return if not defined $path;

    # NEW: leave abstract (NUL-prefixed) names untouched
    return $path if substr($path, 0, 1) eq "\0";

    return Cwd::abs_path($path);
}

sub gv_dir::file_parse {
    my ($path) = @_;
    return if not defined $path;
    my ( $name, $dir, $ext ) = File::Basename::fileparse( $path, qr/\.[^.]+$/ );
    return  ( $name, $dir, $ext );
}

sub gv_dir::file_extension {
    my ($path) = @_;
    return if not defined $path;
    my ( $name, $dir, $ext ) = File::Basename::fileparse( $path, qr/\.[^.]+$/ );
    return $ext;
}

sub gv_dir::base_name {
    my ($path) = @_;
    return if not defined $path;
    my $base_name = File::Basename::basename($path);
    return $base_name;
}
sub gv_dir::dir_name {
    my ($path) = @_;
    return if not defined $path;
    my $dir_name = File::Basename::dirname($path);
    return $dir_name;
}

1;
