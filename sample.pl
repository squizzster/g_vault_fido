#!/usr/bin/env perl

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

my $ring_name = 'memory_2';
my $file      = '/tmp/g_vault_master_secrets_memory_20._gvr_';

# 1) build & save
my ($ring,$err);

($ring,$err) = gv_c::build_cipher_ring(name => $ring_name, master_secret => 'MY_SECRET_IS_NOT_SECURE_AT_ALL_AND_YOU_CAN_FIND_IT_EASILY_IN_MEMORY_BECAUSE_IT_IS_MADE_OF_EASY_TO_READ_WORDS_WITHOUT_ANY_COMPLEXITY_OR_ENTROPY_SO_DO_NOT_USE_THIS_IN_PRODUCTION_SINCE_IT_IS_MEANT_FOR_DEBUGGING_OR_MEMORY_ANALYSIS_ONLY_THIS_IS_A_PLACEHOLDER_NOT_A_REAL_SECRET_SO_PLEASE_REPLACE_IT_WITH_A_STRONG_RANDOM_KEY_BEFORE_DEPLOYMENT_OTHERWISE_YOU_ARE_RISKING_YOUR_SYSTEM_SECURITY_THIS_IS_JUST_ANOTHER_SECTION_OF_EASY_TO_READ_FILLER_TEXT_TO_HELP_PAD_THE_SECRET_TO_A_FIXED_LENGTH_THE_PURPOSE_OF_THIS_FILLER_IS_T');
die "build error: $err\n" if $err;

if ( $ring ) {
    gv_s::save_cipher_ring($ring, $file, 1);
}

# 2) load (put in cache once)
#gv_l::gv_l($file)->();

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

my $x_blob = decode_hex('623936313362353937373366343137656364373234363337366232666438393936656130386437663665613366343837623832376661663661386432333030393b40e0987d6dd75f222dfedfd7caf0402d19f86aca0a131bc3854105c3727e03fea25112e98a4be56399536069d1d4787d90a3bdf1cf46f93382a1a69404ee26efc5a791f7c4d47531ff9f7306e1738a4adf79db8125a300655332e9591f304d6a49da43299e4c6eb83aa79f64ff5c07865e24cfe8593038189b7634bf75b434ddc2992337b6aca18ac09c1024f665cccd6e0226e04bbe6dcbee69d00d98bc41faf65de957987154f5b1c47228aa8f9ae0b9c18f4d7bc23e822b1cda8d5a58073519ca919a7d24077362847f59b8a2d96154c75fabb68900b38128e2c52239aa129f545779b33e1f7b54885922a68ba9c09b5f498c926a01f04bbb487e9184699dcf8f2477553a62c674cdfac5d36c038f8520625ba812ce658409b4083513fcbe6df0c09d06fa7c5d8fa4b9e2698be7c8d2eeb582a6a81052f8e16fb409da1b8b17a6ca68e758c1c3d156392697a08c11e2a3dc3e78f17017003549d3f5c9d7c1f02efbf3');

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
