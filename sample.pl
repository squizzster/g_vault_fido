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
#   • **Node “MACs” are not cryptographic MACs:** The function named
#     “_calculate_node_mac_ref” uses BLAKE2b as a fast, robust hash to
#     detect in-memory node modification or corruption. This is NOT
#     a secure MAC; it is only tamper-evident within process memory.
#     Anyone with access to the structure (and thus the hash input)
#     can recompute the check. (See function comments below.)
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

use gv_c ();    # create
use gv_s ();    # save
use gv_l ();    # load
use gv_e ();    # encrypt
use gv_d ();    # decrypt

my $ring_name = 'memory';
my $file      = '/tmp/g_vault_master_secrets_memory_6._gvr_';

# 1) build & save
my ($ring,$err) = gv_c::build_cipher_ring(name => $ring_name, master_secret => 'MY_SECRET_IS_NOT_SECURE_AT_ALL_AND_YOU_CAN_FIND_IT_EASILY_IN_MEMORY_BECAUSE_IT_IS_MADE_OF_EASY_TO_READ_WORDS_WITHOUT_ANY_COMPLEXITY_OR_ENTROPY_SO_DO_NOT_USE_THIS_IN_PRODUCTION_SINCE_IT_IS_MEANT_FOR_DEBUGGING_OR_MEMORY_ANALYSIS_ONLY_THIS_IS_A_PLACEHOLDER_NOT_A_REAL_SECRET_SO_PLEASE_REPLACE_IT_WITH_A_STRONG_RANDOM_KEY_BEFORE_DEPLOYMENT_OTHERWISE_YOU_ARE_RISKING_YOUR_SYSTEM_SECURITY_THIS_IS_JUST_ANOTHER_SECTION_OF_EASY_TO_READ_FILLER_TEXT_TO_HELP_PAD_THE_SECRET_TO_A_FIXED_LENGTH_THE_PURPOSE_OF_THIS_FILLER_IS_T');
die "build error: $err\n" if $err;

gv_s::save_cipher_ring($ring, $file, 0) and print STDERR "Ring saved.\n";

###$ring_name = 'master_secrets_2';
###$file      = '/tmp/g_vault_master_secrets_2._gvr_';

# 2) load (put in cache once)
gv_l::gv_l($file)->();

# 3) encrypt
my $pepper = '12345678' x 4;   # 32-byte pepper
my $aad    = 'AAD_TEST' x 100;
my $plain  = 'Atoms consist of an extremely small, positively charged nucleus surrounded by a cloud of negatively charged electrons. Although typically the nucleus is less than one ten-thousandth the size of the atom, the nucleus contains more that 99.9% of the mass of the atom. Atoms consist of a central nucleus containing protons and neutrons, surrounded by negatively charged electrons that occupy specific energy levels or orbitals.' x  500;

my $goes = 10000;

for (1 .. $goes) {
    my ($blob, $eerr) = gv_e::encrypt({
        plaintext => $plain,
        pepper    => $pepper,
        key_name  => $ring_name,
        aad       => $aad,
    });
}
#
my ($blob,$eerr) = gv_e::encrypt({
    plaintext => $plain,
    pepper    => $pepper,
    key_name  => $ring_name,
    aad       => $aad,
});

die "encrypt error: $eerr\n" if $eerr;
say "Ciphertext bytes: ", length($blob);

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
die "decrypt error: $derr\n" if $derr;
say "Recovered: " . substr($out,0,200) if defined $out;


sub encode_hex { unpack 'H*', $_[0] }
sub decode_hex { pack 'H*', $_[0] }
