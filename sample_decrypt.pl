#!/usr/bin/env perl
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
my $file      = '/tmp/g_vault_master_secrets_memory_17._gvr_';

# 2) load (put in cache once)
gv_l::gv_l($file)->();

my $pepper = '12345678' x 4;   # 32-byte pepper
my $aad    = 'woof';

use Data::Dump qw(dump);

my $x_blob = decode_hex('623936313362353937373366343137656364373234363337366232666438393936656130386437663665613366343837623832376661663661386432333030393b40e0987d6dd75f222dfedfd7caf0402d19f86aca0a131bc3854105c3727e03fea25112e98a4be56399536069d1d4787d90a3bdf1cf46f93382a1a69404ee26efc5a791f7c4d47531ff9f7306e1738a4adf79db8125a300655332e9591f304d6a49da43299e4c6eb83aa79f64ff5c07865e24cfe8593038189b7634bf75b434ddc2992337b6aca18ac09c1024f665cccd6e0226e04bbe6dcbee69d00d98bc41faf65de957987154f5b1c47228aa8f9ae0b9c18f4d7bc23e822b1cda8d5a58073519ca919a7d24077362847f59b8a2d96154c75fabb68900b38128e2c52239aa129f545779b33e1f7b54885922a68ba9c09b5f498c926a01f04bbb487e9184699dcf8f2477553a62c674cdfac5d36c038f8520625ba812ce658409b4083513fcbe6df0c09d06fa7c5d8fa4b9e2698be7c8d2eeb582a6a81052f8e16fb409da1b8b17a6ca68e758c1c3d156392697a08c11e2a3dc3e78f17017003549d3f5c9d7c1f02efbf3');

my ($xout,$xderr) = gv_d::decrypt({
    cipher_text => $x_blob,
    pepper      => $pepper,
    aad         => "$aad",
});

say "Recovered: [$$] => " . substr($xout,0,200) if defined $xout;
sleep 500;

sub encode_hex { unpack 'H*', $_[0] }
sub decode_hex { pack 'H*', $_[0] }
