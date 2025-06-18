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
my $file      = '/tmp/g_vault_master_secrets_memory_13._gvr_';

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

my $x_blob = decode_hex('623936313362353937373366343137656364373234363337366232666438393936656130386437663665613366343837623832376661663661386432333030394633089ca57ccccf3113c8c89769e91b57d010d35c7ee5c058593055b1577fabdd4bc53eda323a84bdc63b59002c330036b562a79524f3e4a7df165f3b800dbff5b6445d9b644c93773463da20df5847c858a01c5b9b35aa039542700fdc75236f0d68bba9a755d42a13d4001d13665deca9942e207f425f18a62734720dc8e5c0f1c14fdc8928bb45aba07df1a5e00a72d9a8cdb1ec927084830d3c45236c7ec9775431772c3e53ed5688dc07918ec302a51866f90fb6889f099873ef12c942957747dabecfe48b4ccc3063e83580d6b0e38ee1b7dbed85ffe09e8b9e92e4d070d1d300b998fe6f28cecccd749238b155384dc5c5a349d248aa950847d7be35959aff1e9e2381bc0b7f538adca7f61648d3a3e9d6339243be7afc5eff90a09716d21edb8c1552cfb7228e85c510bbdc0862e9333acdb84870854c8ae97017f58e28fdf7562f3bab47f96bdeacaffc28b31975874bce04a65efc411d187d9925b1001f556b');

my ($xout,$xderr) = gv_d::decrypt({
    cipher_text => $x_blob,
    pepper      => $pepper,
    aad         => "$aad",
});

#my $is_ring_equal  = rings_equal ($ring, $ring);

die "decrypt error: $derr\n" if $derr;
say " x $goes";
say "Cipher   : " . encode_hex ( $blob );
say "Recovered: " . substr($out,0,200) if defined $out;
say "Recovered: " . substr($xout,0,200) if defined $xout;

#say "Ring equal [$is_ring_equal].\n";

sub encode_hex { unpack 'H*', $_[0] }
sub decode_hex { pack 'H*', $_[0] }
