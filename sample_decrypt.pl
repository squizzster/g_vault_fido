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
my $file      = '/tmp/g_vault_master_secrets_memory_16._gvr_';

# 2) load (put in cache once)
gv_l::gv_l($file)->();

my $pepper = '12345678' x 4;   # 32-byte pepper
my $aad    = 'woof';

use Data::Dump qw(dump);

my $x_blob = decode_hex('623936313362353937373366343137656364373234363337366232666438393936656130386437663665613366343837623832376661663661386432333030399066b0b3e559adf2150d1c3a37e7299e4dbae8ef4897a0ddeec646197bbbc81807b5205c322050ea5b42db962a33d0941ba1bf0dcf3a7106d8881eb8759bfb0c7425b55de1dadbddffe2d3fb30d2292c4441d654a133c4b372b69c44d402de6613aa0ff905a9d35845fcba10e80a60bc27c6145d3a37c65a6bf79ae30bec776f25e603e2d3786089c369f5fd0f035154ea7ce808184a9ba88e95d281ca1d09bb7ae565a31787c9aac07d1ef46032b7e8612b7902b89accf4536a569763f5e2013ea7cdf798e62b659775efd7eb0ad0f5cd44517664c5b9f464b1ac78f321ab971734d772124125ebf3bc605f88976aebf39b3010d114015fd4a4493b06c9ea25c0e44e423c084f9395ff54bbd458cd3ba57e41c6c1e8c49d624a0261ca2d45694e36a684986f6743904e3b03be715ea7e445bd2fd117997d151a39e3b7af1c3275e1579c00fba486916352d89262d319e8a0844ccd5bcf928b0e6d049c3d62c23dcdc0767a');

my ($xout,$xderr) = gv_d::decrypt({
    cipher_text => $x_blob,
    pepper      => $pepper,
    aad         => "$aad",
});

say "Recovered: [$$] => " . substr($xout,0,200) if defined $xout;
sleep 500;

sub encode_hex { unpack 'H*', $_[0] }
sub decode_hex { pack 'H*', $_[0] }
