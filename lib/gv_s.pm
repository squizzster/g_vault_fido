package gv_s;
use v5.14;
use strict;
use warnings;

use Carp         qw(carp);
use Crypt::Digest::BLAKE2b_256 ();
use Scalar::Util qw(refaddr);
use Crypt::Misc ();

# We do basic authentication with Blake in-case of protocol errors but the script is pre-authenticated so this is integrity not authenticity

sub save_cipher_ring {
    my ( $ring, $file, $overwrite ) = @_;

    print "-----------> SAVING -------> [$ring->{name}] <--------\n";

    unless ( $ring && ref $ring eq 'HASH' && $ring->{name} && $ring->{name_hash} ) {
        carp 'save_cipher_ring: ring missing name_hash';
        return;
    }
    if ( !$overwrite && -e $file ) {
        carp "save_cipher_ring: file '$file' exists and overwrite not allowed";
        return;
    }

    open my $fh, '>', $file
      or carp("save_cipher_ring: cannot open '$file': $!") && return;

    print {$fh} $ring->{name}, "\n"; #  send ther name first

    # header ---
    my $current_blake = 'save_cipher_ring:';

    $current_blake = Crypt::Digest::BLAKE2b_256::blake2b_256_hex( $current_blake . $ring->{name_hash} );
    print {$fh} $ring->{name_hash}, "\t", $current_blake, "\n"; # 1-name-hash

    $current_blake = Crypt::Digest::BLAKE2b_256::blake2b_256_hex( $current_blake . $ring->{mac_key} );
    print {$fh} Crypt::Misc::encode_b64( $ring->{mac_key} // q{} ), "\t", $current_blake, "\n"; # 2-MAC-key
    unless ( exists $ring->{aes_key} && defined $ring->{aes_key} ) {
        carp 'save_cipher_ring: ring missing aes_key';
        close $fh; return;
    }

    $current_blake = Crypt::Digest::BLAKE2b_256::blake2b_256_hex( $current_blake . $ring->{aes_key} );
    print {$fh} Crypt::Misc::encode_b64( $ring->{aes_key} ), "\t", $current_blake, "\n";        # 3-AES-key

    # nodes ---
    my %seen;
    my $node = $ring->{f};
    while ( $node && !$seen{ refaddr $node }++ ) {
        my %raw = $node->('raw');                                   # ← no decrypt!
        $current_blake = Crypt::Digest::BLAKE2b_256::blake2b_256($current_blake . $raw{iv} . $raw{ct} . $raw{tag} );
        print {$fh} join( "\t",
            $raw{index},
            Crypt::Misc::encode_b64( $raw{iv}       ),
            Crypt::Misc::encode_b64( $raw{ct}       ),
            Crypt::Misc::encode_b64( $raw{tag}      ),
            Crypt::Misc::encode_b64( $current_blake ),
        ), "\n";
        $node = $raw{next_node};
    }

    close $fh;
    return 1;
}

1;
