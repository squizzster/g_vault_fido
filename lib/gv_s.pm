package gv_s;
use v5.24;
use strict;
use warnings;

use Carp         qw(carp);
use MIME::Base64 qw(encode_base64);
use Scalar::Util qw(refaddr);

sub save_cipher_ring {
    my ( $ring, $file, $overwrite ) = @_;

    unless ( $ring && ref $ring eq 'HASH' && $ring->{name_hash} ) {
        carp 'save_cipher_ring: ring missing name_hash';
        return;
    }

    if ( !$overwrite && -e $file ) {
        carp "save_cipher_ring: file '$file' exists and overwrite not allowed";
        return;
    }

    open my $fh, '>', $file
      or carp("save_cipher_ring: cannot open '$file': $!") && return;

    print {$fh} $ring->{name_hash}, "\n";

    if ( exists $ring->{mac_key} && defined $ring->{mac_key} ) {
        print {$fh} encode_base64( $ring->{mac_key}, '' ), "\n";
    }
    else {
        print {$fh} "\n";
    }

    my %seen;
    my $node = $ring->{first_node};

    while ( $node && !$seen{ refaddr $node }++ ) {
        my %d = $node->();

        print {$fh} join( "\t",
            $d{index},
            $d{stored_byte},
            $d{mode},
            ( defined $d{param} ? $d{param} : '' ),
        ), "\n";

        $node = $d{next_node};
    }

    close $fh;
    return 1;
}
1;
