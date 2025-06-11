package gv_s;
use v5.24;
use strict;
use warnings;

use Carp         qw(carp);
use MIME::Base64 qw(encode_base64);
use Scalar::Util qw(refaddr);

#────────────────────────────────────────────────────────────────────
sub save_cipher_ring {
    my ($ring,$file,$x) = @_;
    unless ($ring && ref $ring eq 'HASH' && $ring->{name_hash}) {
        carp 'Ring missing name_hash';
        return;
    }
    if (!$x && -e $file) {
        carp "save_cipher_ring: file '$file' exists and overwrite not allowed";
        return;
    }
    open my $fh, '>', $file
        or carp("save_cipher_ring: cannot open '$file': $!"), return;

    print {$fh} "$ring->{name_hash}\n";
    print {$fh} encode_base64($ring->{mac_key},''),"\n";

    my %seen;
    my $node = $ring->{first_node};
    while ($node && !$seen{refaddr($node)}++) {
        my %d = $node->();
        print {$fh} join("\t",
            $d{index},
            $d{stored_byte},
            $d{mode},
            (defined $d{param} ? $d{param} : ''),
        ), "\n";
        $node = $d{next_node};
    }
    close $fh;
    return 1;
}
1;
