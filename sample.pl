#!/usr/bin/env perl

#----------------------------------------------------------------------#
#  crypto_ring_ivy_v2.pl – "Super-ring" ChaCha20-Poly1305 engine
#
#  [HIGH-LEVEL COMMENT BLOCK]
#  ---------------------------------------------------------------------
#  This module implements a closure-based "cipher ring" for secret
#  management, layered with AEAD (ChaCha20-Poly1305). All message-level
#  cryptographic security relies on strong entropy sources, HKDF,
#  and outer Poly1305 MACs.
#
#  IMPORTANT DESIGN NOTES:
#   • **Cryptographic vs. non-cryptographic use:** Some internal
#     components use cryptographic primitives (e.g. BLAKE2b) not for
#     crypto security but as fast, high-integrity structure checks.
#     **The only cryptographic message authentication is via
#     ChaCha20-Poly1305 (Poly1305 tag).**
#   • **Key/IV (nonce) derivation:** Every encryption operation
#     incorporates a full-strength, 64-byte cryptographic random salt,
#     which is always stored with the ciphertext and used in key and
#     nonce derivation. Nonce/IV uniqueness is guaranteed by this
#     design, with entropy from salt, pepper, and master secret
#     inputs.
#   • **No salt/nonce tracking:** The system does NOT persist, log, or
#     cache salts or nonces. Each encryption is independent; all salts
#     and nonces are included in the ciphertext, and the risk of reuse
#     is negligible as the salt is 64 random crypto bytes per message.
#   • **Use of Mersenne Twister:** MT is used as a deterministic
#     mixer/expander seeded with strong cryptographic material—never
#     as a source of cryptographic randomness. This increases domain
#     separation in key/nonce derivation, but does not affect entropy.
#  ---------------------------------------------------------------------
#  Recommended:
#  Run this process in a dedicated SELinux (or equiv.) domain (e.g. myapp_t).
#   As standard baseline, you should always explicitly deny:
#      ptrace (debugging, memory read/write/attach)
#      /proc/<pid>/mem, /proc/<pid>/task/*/mem (process memory access)
#      /dev/mem, /dev/kmem, /proc/kcore (kernel/physical memory)
#      Core dumps (creation/writing)
#  Just allow normal file/network access. (a simple configuration)
#  ---------------------------------------------------------------------

use v5.24;
use strict;
use warnings;
use feature 'say';

use lib 'lib';

use gv_c       ();    # create
use gv_s       ();    # save
use gv_l       ();    # load
use gv_e       ();    # encrypt
use gv_d       ();    # decrypt
use gv_m       ();    # decrypt
use gv_random  ();    # crypto-graphic random bytes

my $ring_name = 'memory';
my $file      = '/tmp/g_vault_master_secrets_memory_11._gvr_';

# 1) build & save
my ($ring,$err);

#($ring,$err) = gv_c::build_cipher_ring(name => $ring_name, master_secret => 'MY_SECRET_IS_NOT_SECURE_AT_ALL_AND_YOU_CAN_FIND_IT_EASILY_IN_MEMORY_BECAUSE_IT_IS_MADE_OF_EASY_TO_READ_WORDS_WITHOUT_ANY_COMPLEXITY_OR_ENTROPY_SO_DO_NOT_USE_THIS_IN_PRODUCTION_SINCE_IT_IS_MEANT_FOR_DEBUGGING_OR_MEMORY_ANALYSIS_ONLY_THIS_IS_A_PLACEHOLDER_NOT_A_REAL_SECRET_SO_PLEASE_REPLACE_IT_WITH_A_STRONG_RANDOM_KEY_BEFORE_DEPLOYMENT_OTHERWISE_YOU_ARE_RISKING_YOUR_SYSTEM_SECURITY_THIS_IS_JUST_ANOTHER_SECTION_OF_EASY_TO_READ_FILLER_TEXT_TO_HELP_PAD_THE_SECRET_TO_A_FIXED_LENGTH_THE_PURPOSE_OF_THIS_FILLER_IS_T');
die "build error: $err\n" if $err;

if ( $ring ) {
    gv_s::save_cipher_ring($ring, $file, 1);
}

# 2) load (put in cache once)
gv_l::gv_l($file)->();

print "\n\n";
my $pepper = '12345678' x 4;   # 32-byte pepper
use Data::Dump qw(dump);

my $msg = "Hello, this is public text.";
my ($sig_blob, $sign_err) = gv_m::sign(
   message  => $msg,
   pepper   => $pepper,
   key_name => $ring_name,
);
die "sign: $sign_err" unless defined $sig_blob;

#print "SIGNED => " . ( encode_hex( $sig_blob ) ) . "\n";

# 5) Verify on the receiving side:
#    (Assumes you’ve loaded the same ring into gv_l cache
#     and have the same $pepper)
my ($ok, $verify_err) = gv_m::verify(
   message        => $msg,
   signature_blob => $sig_blob,
   pepper         => $pepper,
);


if ($ok) {
   say "✅ signature valid! [" . encode_hex($sig_blob) . "].\n";
} else {
   die "❌ verification failed: $verify_err";
}
#$plain  = 'Atoms consist of an extremely small, positively charged nucleus';


# 3) encrypt
my $aad    = 'woof';
my $plain  = 'Atoms consist of an extremely small, positively charged nucleus surrounded by a cloud of negatively charged electrons. Although typically the nucleus is less than one ten-thousandth the size of the atom, the nucleus contains more that 99.9% of the mass of the atom.';

my $goes = 1;
my ($blob, $eerr);

for (1 .. $goes) {
    ($blob, $eerr) = gv_e::encrypt({
        plaintext => $plain,
        pepper    => $pepper,
        key_name  => $ring_name,
        aad       => $aad,
    });
}
#

die "encrypt error: $eerr\n" if $eerr;
#say "Ciphertext bytes: ", length($blob);
#say "Ciphertext bytes: ", encode_hex($blob);

#my $ciphertext = substr($blob, 64 + 64 + 12, length($blob) - 64 - 64 - 12 - 16);

for (1 .. $goes) {
    my ($out,$derr) = gv_d::decrypt({
        cipher_text => $blob,
        pepper      => $pepper,
        aad         => "$aad",
    });
}

# 4) decrypt
my ($out,$derr) = gv_d::decrypt({
    cipher_text => $blob,
    pepper      => $pepper,
    aad         => "$aad",
});

my $x_blob = decode_hex('62393631336235393737336634313765636437323436333736623266643839393665613038643766366561336634383762383237666166366138643233303039dfe9da90183d6a36445f605f689a21fa2129b256a81d19853b7268c41f28c79efaaacfccbe25ba20acb84d5e55e27d908529b6099d90a5c7d783368427c56886a08cb0fbfaec38a16d644233edcf1a8d5a2b3c6cb4d9712c907b5f685a6558c74bd5540f70e2333ae3acb9371a3ec79f2b8133743083c9e54e31d85f47d69a7dc3fe9f0f53003dc570f56ef4be3fc13293a5b343521577c4555f540d1edcd7c15ea1f387af896f1406674562443be639f72f818292aed5dbcf2316643b29a9491ae1149109a7cebc91fa5893849dc33669d56fe12e8eabb4ce22bad73fc6c9d8a74e2714ebece1218079d207e1735994345ae9457b09ae81817ff1e8bd9ffc018655e5dd43288c79443a98d30b7a597413c572b478db57ad71f3d00d5ef2c54b7112a78ba276d8ef8053647ffc1de2bc5acdaf9a553210e736e97a476951d6d420b78281da09bc8d9e118b549a713772214873a755f1c9922c5d7b22af8b89df3b85c4b3ad');

my ($xout,$xderr) = gv_d::decrypt({
    cipher_text => $x_blob,
    pepper      => $pepper,
    aad         => "$aad",
});

#my $is_ring_equal  = rings_equal ($ring, $ring);

die "decrypt error: $derr\n" if $derr;
say " x $goes";
say "Recovered: " . substr($out,0,200) if defined $out;
say "Recovered: " . substr($xout,0,200) if defined $xout;

#say "Ring equal [$is_ring_equal].\n";

sub encode_hex { unpack 'H*', $_[0] }
sub decode_hex { pack 'H*', $_[0] }
