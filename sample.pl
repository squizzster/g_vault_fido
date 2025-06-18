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
my $file      = '/tmp/g_vault_master_secrets_memory_16._gvr_';

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

my $x_blob = decode_hex('623936313362353937373366343137656364373234363337366232666438393936656130386437663665613366343837623832376661663661386432333030399066b0b3e559adf2150d1c3a37e7299e4dbae8ef4897a0ddeec646197bbbc81807b5205c322050ea5b42db962a33d0941ba1bf0dcf3a7106d8881eb8759bfb0c7425b55de1dadbddffe2d3fb30d2292c4441d654a133c4b372b69c44d402de6613aa0ff905a9d35845fcba10e80a60bc27c6145d3a37c65a6bf79ae30bec776f25e603e2d3786089c369f5fd0f035154ea7ce808184a9ba88e95d281ca1d09bb7ae565a31787c9aac07d1ef46032b7e8612b7902b89accf4536a569763f5e2013ea7cdf798e62b659775efd7eb0ad0f5cd44517664c5b9f464b1ac78f321ab971734d772124125ebf3bc605f88976aebf39b3010d114015fd4a4493b06c9ea25c0e44e423c084f9395ff54bbd458cd3ba57e41c6c1e8c49d624a0261ca2d45694e36a684986f6743904e3b03be715ea7e445bd2fd117997d151a39e3b7af1c3275e1579c00fba486916352d89262d319e8a0844ccd5bcf928b0e6d049c3d62c23dcdc0767a');

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
