package gv_d;
use v5.24;
use strict;
use warnings;
use Scalar::Util qw(refaddr);

use Crypt::AuthEnc::ChaCha20Poly1305 qw(chacha20poly1305_decrypt_verify);
use Crypt::KeyDerivation             qw(hkdf);
use Crypt::Digest::BLAKE2b_256       qw(blake2b_256 blake2b_256_hex);
use Crypt::Digest::BLAKE2b_512       qw(blake2b_512);
use Math::Random::MT;
use Carp qw(croak);

use constant {
    MASTER_SECRET_LEN           => 512,
    DYNAMIC_SALT_LEN            => 64,
    MAC_OUTPUT_LEN              => 16,
    PEPPER_LEN                  => 32,
    DETERMINISTIC_COMPONENT_LEN => 32,
    DPRNG_SEED_HASH_LEN         => 32,
    NAME_HASH_HEX_LEN           => 64,
    ERR_DECRYPTION_FAILED       => 'Decryption failed.',
    ERR_INVALID_INPUT           => 'Invalid input provided.',
    ERR_INTERNAL_STATE          => 'Internal state error detected.',
    ERR_RING_NOT_AVAILABLE      => 'Ring not loaded.',
    BLAKE_MAC_TAG               => pack("H*", 'ee4bcef77cb49c70f31de849dccaab24'),
    BLAKE_AAD_TAG               => pack("H*", '83cddaa3fbfcabc498527218b3fa4aa6'),
    BLAKE_DET_TAG               => pack("H*", '3562861b7919fa497b42725d6f9548ae'),
};

my $_undo = sub { my ($m,$p,$b)=@_;
    return ($b ^ $p)                      if $m==0;
    return (($b>>$p)|($b<<(8-$p))) & 0xFF if $m==1;
    return ($b - $p) & 0xFF               if $m==2;
    return (~$b) & 0xFF;
};

my $_det = sub { my ($s)=@_;
    my $h=Crypt::Digest::BLAKE2b_256::blake2b_256(BLAKE_DET_TAG . $s,'',DPRNG_SEED_HASH_LEN);
    my @i=unpack 'N*',$h;
    my $mt=Math::Random::MT->new(@i);
    pack 'N*',map{$mt->irand}1..(DETERMINISTIC_COMPONENT_LEN/4);
};
my $_recover = sub {
    my($ring,$salt,$pep)=@_;
    return(undef,'bad ring')             unless ref($ring) eq 'HASH';
    return(undef,'bad salt')             if length($salt)!=DYNAMIC_SALT_LEN;
    return(undef,'bad pepper')           if length($pep)!=PEPPER_LEN;
    my @sb=unpack'C*',$salt; my@pb=unpack'C*',$pep;
    my $k=$ring->{mac_key};
    my(%seen,@out);my$n=$ring->{first_node};
    while($n&&!$seen{refaddr($n)}++){
        my%d=$n->();
        my$orig=$_undo->($d{mode},$d{param},$d{stored_byte});
        my$pep=$orig^$pb[$d{index}%PEPPER_LEN];
        push@out,$pep^$sb[$d{index}%DYNAMIC_SALT_LEN];
        $n=$d{next_node};
    }
    return(undef,'cycle')unless@out==MASTER_SECRET_LEN;
    return(pack('C*',@out),undef);
};
my $_derive=sub{
    my($sm,$salt,$pep)=@_;
    my$det=$_det->($sm.$salt.$pep);
    my$ikm=$sm.$pep.$det;
    my$k=hkdf($ikm,$salt,'BLAKE2b_256',32,'key');
    my$n=hkdf($ikm,$salt,'BLAKE2b_256',12,'nonce');
    [$k,$n];
};

#────────────────────────────────────────────────────────────────────
sub decrypt {
    my %a = @_==1 ? %{$_[0]} : @_;
    my ($blob,$pepper,$aad) = @a{qw(cipher_text pepper aad)};
    $aad //= '';

    # Domain tag for AAD
    my $aad_hashed = Crypt::Digest::BLAKE2b_512::blake2b_512(BLAKE_AAD_TAG . $aad);

    return (undef,ERR_INVALID_INPUT) unless defined $blob;
    return (undef,ERR_INVALID_INPUT) unless defined($pepper) && length($pepper)==PEPPER_LEN;

    my $min = NAME_HASH_HEX_LEN + DYNAMIC_SALT_LEN + 12 + 16;
    return (undef,ERR_INVALID_INPUT) if length($blob) < $min;

    my $name_hash = substr($blob,0,NAME_HASH_HEX_LEN,'');
    my $salt      = substr($blob,0,DYNAMIC_SALT_LEN,'');
    my $nonce     = substr($blob,0,12,'');
    my $tag       = substr($blob,-16,16,'');
    my $ct        = $blob;

    my $ring = gv_l::get_cached_ring($name_hash)
        or return (undef,ERR_RING_NOT_AVAILABLE);

    my ($sm,$er1) = $_recover->($ring,$salt,$pepper);
    return (undef,ERR_INTERNAL_STATE) if $er1 && $er1 =~ /MAC mismatch|cycle/;
    return (undef,ERR_DECRYPTION_FAILED) if $er1;

    my ($k,$nck) = @{ $_derive->($sm,$salt,$pepper) };
    return (undef,ERR_DECRYPTION_FAILED) if $nck ne $nonce;

    my $pt;
    eval { $pt = chacha20poly1305_decrypt_verify($k,$nonce,$aad_hashed,$ct,$tag); 1 }
        or return (undef,ERR_DECRYPTION_FAILED);

    return ($pt,undef);
}
1;

