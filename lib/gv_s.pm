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

    # header ---
    print {$fh} $ring->{name_hash}, "\n";                           # 1-name-hash
    print {$fh} encode_base64( $ring->{mac_key} // q{}, '' ), "\n"; # 2-MAC-key
    unless ( exists $ring->{aes_key} && defined $ring->{aes_key} ) {
        carp 'save_cipher_ring: ring missing aes_key';
        close $fh; return;
    }
    print {$fh} encode_base64( $ring->{aes_key}, '' ), "\n";        # 3-AES-key

    # nodes ---
    my %seen;
    my $node = $ring->{first_node};
    while ( $node && !$seen{ refaddr $node }++ ) {
        my %raw = $node->('raw');                                   # ← no decrypt!
        print {$fh} join( "\t",
            $raw{index},
            encode_base64( $raw{iv},  '' ),
            encode_base64( $raw{ct},  '' ),
            encode_base64( $raw{tag}, '' ),
        ), "\n";
        $node = $raw{next_node};
    }

    close $fh;
    return 1;
}

1;
