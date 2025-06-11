package gv_e;
use v5.24;
use strict;
use warnings;
use Scalar::Util qw(refaddr);

use Crypt::PRNG                      qw(random_bytes);
use Crypt::AuthEnc::ChaCha20Poly1305 qw(chacha20poly1305_encrypt_authenticate);
use Crypt::KeyDerivation             qw(hkdf);
use Crypt::Digest::BLAKE2b_256       qw(blake2b_256 blake2b_256_hex);
use Crypt::Digest::BLAKE2b_512 qw(blake2b_512);

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
    ERR_ENCRYPTION_FAILED       => 'Encryption failed.',
    ERR_INVALID_INPUT           => 'Invalid input provided.',
    ERR_INTERNAL_STATE          => 'Internal state error detected.',
    ERR_RING_NOT_AVAILABLE      => 'Ring not loaded.',
};

# helpers
my $_apply = sub { my ($m,$p,$b)=@_;
    return ($b ^ $p)                      if $m==0;
    return (($b<<$p)|($b>>(8-$p))) & 0xFF if $m==1;
    return ($b + $p) & 0xFF               if $m==2;
    return (~$b) & 0xFF;
};
my $_undo = sub { my ($m,$p,$b)=@_;
    return ($b ^ $p)                      if $m==0;
    return (($b>>$p)|($b<<(8-$p))) & 0xFF if $m==1;
    return ($b - $p) & 0xFF               if $m==2;
    return (~$b) & 0xFF;
};
my $_mac = sub {
    my ($k,$ob,$i)=@_;
    substr blake2b_256("CryptoRingNodeMAC$k".pack('CN',$ob,$i)),0,MAC_OUTPUT_LEN;
};
my $_det = sub {
    my ($seed)=@_;
    my $h = blake2b_256($seed,'',DPRNG_SEED_HASH_LEN);
    my @i = unpack 'N*',$h;
    my $mt = Math::Random::MT->new(@i);
    pack 'N*', map { $mt->irand } 1..(DETERMINISTIC_COMPONENT_LEN/4);
};

# internal
my $_recover = sub {
    my ($ring,$salt,$pepper)=@_;
    return (undef,'bad ring') unless ref($ring) eq 'HASH';
    return (undef,'bad salt') if length($salt)!=DYNAMIC_SALT_LEN;
    return (undef,'bad pepper') if length($pepper)!=PEPPER_LEN;

    my @sb = unpack 'C*',$salt;
    my @pb = unpack 'C*',$pepper;
    my $k  = $ring->{mac_key};
    my (%seen,@out); my $n=$ring->{first_node};
    while ($n && !$seen{refaddr($n)}++) {
        my %d = $n->();
        my $orig = $_undo->($d{mode},$d{param},$d{stored_byte});
        return (undef,'MAC mismatch') if $_mac->($k,$orig,$d{index}) ne $d{mac};
        my $pep = $orig ^ $pb[$d{index}%PEPPER_LEN];
        push @out, $pep ^ $sb[$d{index}%DYNAMIC_SALT_LEN];
        $n = $d{next_node};
    }
    return (undef,'cycle') unless @out==MASTER_SECRET_LEN;
    return (pack('C*',@out),undef);
};
my $_derive = sub {
    my ($sm,$salt,$pep)=@_;
    my $det = $_det->($sm.$salt.$pep);
    my $ikm = $sm.$pep.$det;
    my $k   = hkdf($ikm,$salt,'SHA256',32,'key');
    my $n   = hkdf($ikm,$salt,'SHA256',12,'nonce');
    [$k,$n];
};

#────────────────────────────────────────────────────────────────────
sub encrypt {
    my %a = @_==1 ? %{$_[0]} : @_;
    my ($pt,$pep,$name,$aad) = @a{qw(plaintext pepper key_name aad)};
    $aad //= '___empty___';
    my $aad_hashed = blake2b_512($aad);

    return (undef,ERR_INVALID_INPUT) unless defined $pt;
    return (undef,ERR_INVALID_INPUT) unless defined($pep) && length($pep)==PEPPER_LEN;
    return (undef,ERR_INVALID_INPUT) unless defined $name;

    my $name_hash = blake2b_256_hex($name);
    my $ring      = gv_l::get_cached_ring($name_hash)
        or return (undef,ERR_RING_NOT_AVAILABLE);

    my $salt = random_bytes(DYNAMIC_SALT_LEN);
    my ($sm,$er1) = $_recover->($ring,$salt,$pep);
    return (undef,ERR_INTERNAL_STATE) if $er1 && $er1 =~ /MAC mismatch|cycle/;
    return (undef,ERR_ENCRYPTION_FAILED) if $er1;

    my ($k,$nonce) = @{ $_derive->($sm,$salt,$pep) };

    my ($ct,$tag);
    eval { ($ct,$tag)=chacha20poly1305_encrypt_authenticate($k,$nonce,$aad_hashed,$pt); 1 }
        or return (undef,ERR_ENCRYPTION_FAILED);

    return ($name_hash.$salt.$nonce.$ct.$tag, undef);
}
1;

