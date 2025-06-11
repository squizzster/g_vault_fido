package gv_s;
use v5.24;
use strict;
use warnings;

use Carp         qw(croak);
use MIME::Base64 qw(encode_base64);
use Scalar::Util qw(refaddr);

#────────────────────────────────────────────────────────────────────
sub save_cipher_ring {
    my ($ring,$file,$x) = @_;
    my $name_hash = $ring->{name_hash}
        or croak 'Ring missing name_hash';

    open my $fh, '>', $file
        or croak "save_cipher_ring: cannot open '$file': $!";

    print {$fh} "$name_hash\n";                      # 1) name-hash
    print {$fh} encode_base64($ring->{mac_key},''),"\n";  # 2) MAC key

    my %seen;
    my $node = $ring->{first_node};
    while ($node && !$seen{refaddr($node)}++) {
        my %d = $node->();
        print {$fh} join("\t",
            $d{index},
            $d{stored_byte},
            encode_base64($d{mac},''),
            $d{mode},
            (defined $d{param} ? $d{param} : ''),
        ), "\n";
        $node = $d{next_node};
    }
    close $fh;
}
1;
