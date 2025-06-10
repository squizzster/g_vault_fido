#!/usr/bin/env perl
#----------------------------------------------------------------------#
#  crypto_ring_ivy_v2.pl – "Super‑ring" ChaCha20‑Poly1305 engine
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
use Scalar::Util;

# --- CPAN modules -----------------------------------------------------#
use Crypt::PRNG qw(random_bytes);
use Crypt::AuthEnc::ChaCha20Poly1305 qw(
    chacha20poly1305_encrypt_authenticate
    chacha20poly1305_decrypt_verify
);
use Crypt::KeyDerivation qw(hkdf); # For HKDF-SHA256
BEGIN { require Digest::BLAKE2; Digest::BLAKE2->import('blake2b'); } # For MACs, param derivation, and DPRNG seeding
use Math::Random::MT; # For generating the deterministic component

use Carp qw(croak); # Still used for compile-time checks.
use Test::More ();

#-----------------------------------------------------------------------
# CONSTANTS – edit with care
#-----------------------------------------------------------------------
use constant {
    MASTER_SECRET_LEN           => 512,
    DYNAMIC_SALT_LEN            => 64,
    MAC_KEY_LEN                 => 32,
    MAC_OUTPUT_LEN              => 16,
    PEPPER_LEN                  => 32,
    DETERMINISTIC_COMPONENT_LEN => 32,
    DPRNG_SEED_HASH_LEN         => 32,

    # Generic Error Messages
    ERR_OPERATION_FAILED        => "Processing error.", 
    ERR_ENCRYPTION_FAILED       => "Encryption failed.",
    ERR_DECRYPTION_FAILED       => "Decryption failed.",
    ERR_BUILD_FAILED            => "Ring construction failed.",
    ERR_INVALID_INPUT           => "Invalid input provided.",
    ERR_INTERNAL_STATE          => "Internal state error detected.",
};

# Compile-time checks
croak "DETERMINISTIC_COMPONENT_LEN must be a multiple of 4" if DETERMINISTIC_COMPONENT_LEN % 4 != 0;
croak "DPRNG_SEED_HASH_LEN must be a multiple of 4" if DPRNG_SEED_HASH_LEN % 4 != 0;

# Declare all code references
my $_apply_transform_ref;
my $_undo_transform_ref;
my $_calculate_node_mac_ref;
my $build_cipher_ring_ref;
my $generate_dynamic_salt_ref;
my $_recover_salted_master_ref;
my $_generate_deterministic_component_ref;
my $_derive_key_nonce_ref;
my $encrypt_ref;
my $decrypt_ref;
my $_selftest_replan_ref;
my $_cli_demo_ref;

#-----------------------------------------------------------------------
#  Reversible 8‑bit operations
#-----------------------------------------------------------------------
$_apply_transform_ref = sub {
    my ($mode, $param, $byte) = @_;
    return ($byte ^ $param)            if $mode == 0;
    return (($byte << $param) | ($byte >> (8 - $param))) & 0xFF if $mode == 1;
    return ($byte + $param) & 0xFF     if $mode == 2;
    return (~$byte) & 0xFF;
};

$_undo_transform_ref = sub {
    my ($mode, $param, $byte) = @_;
    return ($byte ^ $param)            if $mode == 0;
    return (($byte >> $param) | ($byte << (8 - $param))) & 0xFF if $mode == 1;
    return ($byte - $param) & 0xFF     if $mode == 2;
    return (~$byte) & 0xFF;
};

#-----------------------------------------------------------------------
#  _calculate_node_mac
#-----------------------------------------------------------------------
$_calculate_node_mac_ref = sub {
    my ($mac_key_to_use, $original_byte, $index) = @_;
    my $input = "CryptoRingNodeMAC" . $mac_key_to_use . pack('CN', $original_byte, $index);
    return substr(blake2b($input), 0, MAC_OUTPUT_LEN);
};

#-----------------------------------------------------------------------
#  build_cipher_ring( $master_secret_input ) → ($ring_object, $err_msg_or_undef)
#-----------------------------------------------------------------------
$build_cipher_ring_ref = sub {
    my ($master_secret_input) = @_;
    my $master_s = defined $master_secret_input ? $master_secret_input : random_bytes(MASTER_SECRET_LEN);

    unless (defined $master_s && length($master_s) == MASTER_SECRET_LEN) {
        return (undef, ERR_BUILD_FAILED); 
    }

    my $base_mac_key_for_nodes = random_bytes(MAC_KEY_LEN);
    my @bytes = unpack 'C*', $master_s;
    my @closures;
    my @next_ref;

    for my $i (0 .. $#bytes) {
        my $transform_seed = blake2b($master_s . pack('N', $i), "", 2);
        my ($mode_raw, $param_raw) = unpack 'CC', $transform_seed;
        my $mode = $mode_raw % 4;
        my $param;
        if ($mode == 0) { $param = $param_raw; }
        elsif ($mode == 1) { $param = 1 + ($param_raw % 7); }
        elsif ($mode == 2) { $param = $param_raw; }
        else { $param = 0; }

        my $original_byte = $bytes[$i];
        my $stored_byte   = $_apply_transform_ref->($mode, $param, $original_byte);
        my $mac           = $_calculate_node_mac_ref->($base_mac_key_for_nodes, $original_byte, $i);

        my $next;
        push @next_ref, \$next;
        push @closures, sub {
            return (
                index       => $i,
                stored_byte => $stored_byte,
                mac         => $mac,
                mode        => $mode,
                param       => $param,
                next_node   => $next
            );
        };
    }

    for my $i (0 .. $#closures) {
        ${$next_ref[$i]} = $closures[($i + 1) % @closures];
    }

    my $ring_object = {
        first_node        => $closures[0],
        mac_key           => $base_mac_key_for_nodes,
    };
    
    return ($ring_object, undef); # Success
};

#-----------------------------------------------------------------------
#  generate_dynamic_salt() -> $salt
#-----------------------------------------------------------------------
$generate_dynamic_salt_ref = sub {
    return random_bytes(DYNAMIC_SALT_LEN);
};

#-----------------------------------------------------------------------
#  _recover_salted_master → ($recovered_bytes, $internal_err_msg_or_undef)
#-----------------------------------------------------------------------
$_recover_salted_master_ref = sub {
    my ($ring_object, $dynamic_salt, $runtime_pepper) = @_;

    unless (defined $ring_object && ref($ring_object) eq 'HASH' && exists $ring_object->{first_node} && exists $ring_object->{mac_key}) {
        return (undef, "InternalRecover: Invalid ring object structure provided.");
    }
    unless (defined $dynamic_salt && length($dynamic_salt) == DYNAMIC_SALT_LEN) {
        return (undef, "InternalRecover: Invalid dynamic salt provided.");
    }
    unless (defined $runtime_pepper && length($runtime_pepper) == PEPPER_LEN) {
        return (undef, "InternalRecover: Invalid runtime pepper provided.");
    }

    my %seen_closures;
    my @salted_out_bytes;
    my @salt_bytes = unpack 'C*', $dynamic_salt;
    my @pepper_bytes = unpack 'C*', $runtime_pepper;
    my $base_mac_key = $ring_object->{mac_key};

    my $current_closure_ref = $ring_object->{first_node};
    my $count = 0;

    unless (defined $current_closure_ref && ref($current_closure_ref) eq 'CODE') {
        return (undef, "InternalRecover: Ring's first_node is not a valid code reference.");
    }

    while ($current_closure_ref && !$seen_closures{Scalar::Util::refaddr($current_closure_ref)}++ && $count <= MASTER_SECRET_LEN) {
        my %node_data;
        eval { %node_data = $current_closure_ref->(); 1; } or do {
            my $eval_err = $@ || "Unknown error calling node closure";
            chomp $eval_err;
            return (undef, "InternalRecover: Error executing node closure at index $count: $eval_err");
        };

        unless (exists $node_data{mode} && exists $node_data{param} && exists $node_data{stored_byte} && exists $node_data{mac} && exists $node_data{index}) {
            return (undef, "InternalRecover: Incomplete data from node closure at effective index $count.");
        }
        
        my $original_master_byte_candidate = $_undo_transform_ref->($node_data{mode}, $node_data{param}, $node_data{stored_byte});

        my $expected_node_mac = $_calculate_node_mac_ref->($base_mac_key, $original_master_byte_candidate, $node_data{index});
        unless (defined $expected_node_mac && $expected_node_mac eq $node_data{mac}) {
            return (undef, "InternalRecover: Base MAC mismatch at index $node_data{index}. Ring integrity compromised.");
        }

        my $peppered_master_byte = $original_master_byte_candidate ^ $pepper_bytes[$node_data{index} % PEPPER_LEN];
        my $salted_byte = $peppered_master_byte ^ $salt_bytes[$node_data{index} % DYNAMIC_SALT_LEN];
        push @salted_out_bytes, $salted_byte;

        $current_closure_ref = $node_data{next_node};
        if (defined $current_closure_ref && ref($current_closure_ref) ne 'CODE') {
            return (undef, "InternalRecover: Ring's next_node is not a valid code reference at index $node_data{index}.");
        }
        $count++;
    }

    if (@salted_out_bytes != MASTER_SECRET_LEN) {
        return (undef, "InternalRecover: Cycle error or malformed ring. Expected ".MASTER_SECRET_LEN." nodes, processed ".@salted_out_bytes.".");
    }

    return (pack('C*', @salted_out_bytes), undef); # Success
};

#-----------------------------------------------------------------------
#  _generate_deterministic_component
#-----------------------------------------------------------------------
$_generate_deterministic_component_ref = sub {
    my ($seed_material) = @_;
    my $mt_seed_hash = blake2b($seed_material, "", DPRNG_SEED_HASH_LEN);
    my @seed_integers = unpack("N*", $mt_seed_hash);
    my $mt_rng = Math::Random::MT->new(@seed_integers);
    my @component_ints;
    my $num_ints_needed = DETERMINISTIC_COMPONENT_LEN / 4;
    for (1 .. $num_ints_needed) {
        push @component_ints, $mt_rng->irand();
    }
    return pack('N*', @component_ints);
};

#-----------------------------------------------------------------------
#  _derive_key_nonce → ([$key, $nonce], $internal_err_msg_or_undef)
#-----------------------------------------------------------------------
$_derive_key_nonce_ref = sub {
    my ($salted_master_after_pepper_and_salt_ops, $dynamic_salt, $runtime_pepper) = @_;

    unless (defined $runtime_pepper && length($runtime_pepper) == PEPPER_LEN) {
        return (undef, "InternalDerive: Invalid runtime pepper for key derivation.");
    }
    unless (defined $salted_master_after_pepper_and_salt_ops && length($salted_master_after_pepper_and_salt_ops) == MASTER_SECRET_LEN) {
         return (undef, "InternalDerive: Invalid salted_master for key derivation.");
    }
    unless (defined $dynamic_salt && length($dynamic_salt) == DYNAMIC_SALT_LEN) {
         return (undef, "InternalDerive: Invalid dynamic_salt for key derivation.");
    }

    my $deterministic_component;
    eval {
        my $seed_material_for_dprng = $salted_master_after_pepper_and_salt_ops . $dynamic_salt . $runtime_pepper;
        $deterministic_component = $_generate_deterministic_component_ref->($seed_material_for_dprng);
        1; 
    } or do {
        my $eval_err = $@ || "Unknown error generating deterministic component";
        chomp $eval_err;
        return (undef, "InternalDerive: Failed to generate deterministic component: $eval_err");
    };

    my $ikm = $salted_master_after_pepper_and_salt_ops . $runtime_pepper . $deterministic_component;

    my $key_info   = "ChaCha20-Poly1305 Key for CryptoRingIvy v2.4"; 
    my $nonce_info = "ChaCha20-Poly1305 Nonce for CryptoRingIvy v2.4";

    my ($key, $nonce);
    eval {
        $key   = hkdf($ikm, $dynamic_salt, 'SHA256', 32, $key_info);
        $nonce = hkdf($ikm, $dynamic_salt, 'SHA256', 12, $nonce_info);
        1; 
    } or do {
        my $eval_err = $@ || "Unknown error during HKDF";
        chomp $eval_err;
        return (undef, "InternalDerive: HKDF operation failed: $eval_err");
    };
    
    unless (defined $key && defined $nonce) {
        return (undef, "InternalDerive: HKDF returned undefined key or nonce without error.");
    }

    return ([$key, $nonce], undef); # Success
};

#-----------------------------------------------------------------------
#  encrypt( %args ) → ($ciphertext_blob, $err_msg_or_undef)
#-----------------------------------------------------------------------
$encrypt_ref = sub {
    my (%args) = @_;
    my $ring_object = $args{ring_object};
    my $plaintext   = $args{plaintext};
    my $pepper      = $args{pepper};
    my $aad         = $args{aad} // "";

    unless (defined $ring_object && ref($ring_object) eq 'HASH' && exists $ring_object->{first_node}) {
        return (undef, ERR_INVALID_INPUT);
    }
    unless (defined $plaintext) {
        return (undef, ERR_INVALID_INPUT);
    }
    unless (defined $pepper && length($pepper) == PEPPER_LEN) {
        return (undef, ERR_INVALID_INPUT);
    }

    my $dynamic_salt = $generate_dynamic_salt_ref->();

    my ($salted_master, $err_recover) = $_recover_salted_master_ref->($ring_object, $dynamic_salt, $pepper);
    if ($err_recover) {
        if ($err_recover =~ /MAC mismatch|Ring integrity|Cycle error|malformed ring/i) {
            return (undef, ERR_INTERNAL_STATE);
        }
        return (undef, ERR_ENCRYPTION_FAILED);
    }

    my ($key_nonce_arr, $err_derive) = $_derive_key_nonce_ref->($salted_master, $dynamic_salt, $pepper);
    if ($err_derive) {
        return (undef, ERR_ENCRYPTION_FAILED);
    }
    my ($k, $n) = @$key_nonce_arr;

    my ($ct, $tag);
    eval {
        ($ct, $tag) = chacha20poly1305_encrypt_authenticate($k, $n, $aad, $plaintext);
        1;
    } or do {
        my $eval_err = $@ || "Unknown error during chacha20poly1305_encrypt_authenticate";
        chomp $eval_err;
        return (undef, ERR_ENCRYPTION_FAILED);
    };

    unless (defined $ct && defined $tag) {
        return (undef, ERR_ENCRYPTION_FAILED);
    }

    return ($dynamic_salt . $n . $ct . $tag, undef); # Success
};

#-----------------------------------------------------------------------
#  decrypt( %args ) → ($plaintext, $err_msg_or_undef)
#-----------------------------------------------------------------------
$decrypt_ref = sub {
    my (%args) = @_;
    my $ring_object     = $args{ring_object};
    my $ciphertext_blob = $args{ciphertext_blob};
    my $pepper          = $args{pepper};
    my $aad             = $args{aad} // "";

    unless (defined $ring_object && ref($ring_object) eq 'HASH' && exists $ring_object->{first_node}) {
        return (undef, ERR_INVALID_INPUT);
    }
    unless (defined $ciphertext_blob) {
        return (undef, ERR_INVALID_INPUT);
    }
    unless (defined $pepper && length($pepper) == PEPPER_LEN) {
        return (undef, ERR_INVALID_INPUT);
    }

    my $salt_len = DYNAMIC_SALT_LEN();
    my $nonce_len = 12;
    my $tag_len   = 16;
    my $min_len   = $salt_len + $nonce_len + $tag_len;

    if (length($ciphertext_blob) < $min_len) {
        return (undef, ERR_INVALID_INPUT); 
    }

    my $cb_copy = $ciphertext_blob; 
    my $dynamic_salt_from_blob = substr($cb_copy, 0, $salt_len, '');
    my $nonce_from_blob        = substr($cb_copy, 0, $nonce_len, '');
    my $tag_from_blob          = substr($cb_copy, -$tag_len, $tag_len, '');                                                                       
    my $ct_only                = $cb_copy;

    my ($salted_master, $err_recover) = $_recover_salted_master_ref->($ring_object, $dynamic_salt_from_blob, $pepper);
    if ($err_recover) {
        if ($err_recover =~ /MAC mismatch|Ring integrity|Cycle error|malformed ring/i) {
            return (undef, ERR_INTERNAL_STATE);
        }
        return (undef, ERR_DECRYPTION_FAILED);
    }

    my ($key_nonce_arr, $err_derive) = $_derive_key_nonce_ref->($salted_master, $dynamic_salt_from_blob, $pepper);
    if ($err_derive) {
        return (undef, ERR_DECRYPTION_FAILED);
    }
    my ($k, $derived_n) = @$key_nonce_arr;

    unless ($nonce_from_blob eq $derived_n) {
        return (undef, ERR_DECRYPTION_FAILED); 
    }

    my $pt;
    eval {
        $pt = chacha20poly1305_decrypt_verify($k, $derived_n, $aad, $ct_only, $tag_from_blob);
        1;
    } or do {
        my $eval_err = $@ || "Unknown error during chacha20poly1305_decrypt_verify";
        chomp $eval_err;
        return (undef, ERR_DECRYPTION_FAILED);
    };
    
    unless (defined $pt) { 
        return (undef, ERR_DECRYPTION_FAILED);
    }
    
    return ($pt, undef); # Success
};

#-----------------------------------------------------------------------
#  _selftest_replan() - UPDATED for new error handling
#-----------------------------------------------------------------------
$_selftest_replan_ref = sub {
    Test::More::plan tests => 15; # Adjusted plan for new error tests

    eval { require Scalar::Util; Scalar::Util->import('refaddr'); }
      or ($ENV{SKIP_REFADDR_TEST} ? Test::More::skip("Scalar::Util not available", 15) : croak "Scalar::Util is required: $@");
    eval { require Math::Random::MT; }
      or ($ENV{SKIP_REFADDR_TEST} ? Test::More::skip("Math::Random::MT not available", 15) : croak "Math::Random::MT is required: $@");

    my $master_s = random_bytes(MASTER_SECRET_LEN);
    my ($ring, $err_build) = $build_cipher_ring_ref->($master_s);
    Test::More::ok(!$err_build && defined $ring, '0. build_cipher_ring_ref success')
        or Test::More::diag("Build error: $err_build");
    
    # Terminate tests if ring build fails, as other tests depend on it.
    unless (defined $ring) {
        Test::More::diag("Cannot proceed with tests as ring building failed.");
        # Mark remaining tests as skipped or failed if Test::More supports it easily,
        # otherwise they will just not run or fail due to undef $ring.
        # For simplicity here, we'll let them fail if $ring is undef.
        # A more robust test suite might use Test::More::BAIL_OUT().
        return;
    }

    my $plain    = "This is a secret message, v2.4: daemon-ready core and consumers.";
    my $pepper   = random_bytes(PEPPER_LEN);
    my $aad_ok   = "header_v2.4_ok";
    my $aad_wrong= "header_v2.4_wrong";

    # Test 1: Round trip
    my ($blob1, $err_enc1) = $encrypt_ref->(ring_object=>$ring, plaintext=>$plain, pepper=>$pepper, aad=>$aad_ok);
    Test::More::ok(!$err_enc1 && defined $blob1, '1a. encrypt success') or Test::More::diag("Encrypt error: $err_enc1");
    
    my ($round_trip1, $err_dec1) = $decrypt_ref->(ring_object=>$ring, ciphertext_blob=>$blob1, pepper=>$pepper, aad=>$aad_ok);
    Test::More::ok(!$err_dec1 && defined $round_trip1, '1b. decrypt success') or Test::More::diag("Decrypt error: $err_dec1");
    Test::More::is($round_trip1, $plain, '1c. round‑trip plaintext matches');

    # Test 2: Decryption fails with wrong dynamic salt (manipulated blob)
    my $dynamic_salt_for_blob2 = $generate_dynamic_salt_ref->(); 
    my $rest_of_blob1  = substr($blob1, DYNAMIC_SALT_LEN); 
    my $tampered_blob_wrong_salt = $dynamic_salt_for_blob2 . $rest_of_blob1;
    my ($dec_res2, $err_dec2) = $decrypt_ref->(ring_object=>$ring, ciphertext_blob=>$tampered_blob_wrong_salt, pepper=>$pepper, aad=>$aad_ok);
    Test::More::ok(defined $err_dec2 && $err_dec2 eq ERR_DECRYPTION_FAILED, '2. decryption fails with explicitly wrong dynamic salt');
    Test::More::is($dec_res2, undef, '2b. plaintext is undef on wrong salt');

    # Test 3: Base MAC tamper detection (via _recover_salted_master_ref directly for specific internal error)
    my $temp_ring_for_mac_test = { %$ring }; # Shallow copy
    my $original_first_node_sub_t3 = $temp_ring_for_mac_test->{first_node};
    my $bad_mac_closure = sub {
        my %data = $original_first_node_sub_t3->();
        $data{mac} = $data{mac} ^ ("\xAA" x MAC_OUTPUT_LEN); # Corrupt base MAC
        return %data;
    };
    $temp_ring_for_mac_test->{first_node} = $bad_mac_closure;
    my $salt_for_mac_test = $generate_dynamic_salt_ref->();
    my ($rec_res3, $rec_err3) = $_recover_salted_master_ref->($temp_ring_for_mac_test, $salt_for_mac_test, $pepper);
    Test::More::ok(defined $rec_err3 && $rec_err3 =~ /Base MAC mismatch/i, '3. Base MAC tamper detection fires (internal check)');
    # Test how encrypt handles this internal state error
    my ($enc_res3, $enc_err3) = $encrypt_ref->(ring_object=>$temp_ring_for_mac_test, plaintext=>$plain, pepper=>$pepper, aad=>$aad_ok);
    Test::More::ok(defined $enc_err3 && $enc_err3 eq ERR_INTERNAL_STATE, '3b. encrypt maps MAC mismatch to ERR_INTERNAL_STATE');


    # Test 4: Cycle length check (via _recover_salted_master_ref directly)
    my $temp_ring_for_cycle_test = { %$ring }; # Shallow copy
    my $original_closure_code_t4 = $temp_ring_for_cycle_test->{first_node};
    my $broken_closure_t4 = sub {
        my %data = $original_closure_code_t4->();
        $data{next_node} = undef if $data{index} == MASTER_SECRET_LEN() / 2; # Break chain
        return %data;
    };
    $temp_ring_for_cycle_test->{first_node} = $broken_closure_t4;
    my ($cycle_res4, $cycle_err4) = $_recover_salted_master_ref->($temp_ring_for_cycle_test, $generate_dynamic_salt_ref->(), $pepper);
    Test::More::ok(defined $cycle_err4 && $cycle_err4 =~ /Cycle error or malformed ring/i, '4. Cycle length/malformed ring detection fires (internal check)');
    # Test how encrypt handles this
    my ($enc_res4, $enc_err4) = $encrypt_ref->(ring_object=>$temp_ring_for_cycle_test, plaintext=>$plain, pepper=>$pepper, aad=>$aad_ok);
    Test::More::ok(defined $enc_err4 && $enc_err4 eq ERR_INTERNAL_STATE, '4b. encrypt maps cycle error to ERR_INTERNAL_STATE');


    # Test 5 & 6: Different dynamic salts produce different ciphertexts (assuming encrypt succeeds for blob3)
    my ($blob3, $err_enc3) = $encrypt_ref->(ring_object=>$ring, plaintext=>$plain, pepper=>$pepper, aad=>$aad_ok);
    Test::More::ok(!$err_enc3 && defined $blob3, '5a. encrypt for blob3 success') or Test::More::diag("Encrypt blob3 error: $err_enc3");
    if (defined $blob1 && defined $blob3) {
        Test::More::isnt($blob1, $blob3, '5b. different dynamic salts produce different ciphertexts');
        Test::More::isnt(substr($blob1,0,DYNAMIC_SALT_LEN), substr($blob3,0,DYNAMIC_SALT_LEN), '6. salts themselves are different');
    } else {
        Test::More::fail('5b. skipped due to previous encrypt failure');
        Test::More::fail('6. skipped due to previous encrypt failure');
    }


    # Test 7 & 8: AAD protection
    my ($blob_aad_ok, $err_enc_aad) = $encrypt_ref->(ring_object=>$ring, plaintext=>$plain, pepper=>$pepper, aad=>$aad_ok);
    Test::More::ok(!$err_enc_aad && defined $blob_aad_ok, "7a. Encrypt with correct AAD succeeds");
    my ($pt_aad_ok, $err_dec_aad_ok)   = $decrypt_ref->(ring_object=>$ring, ciphertext_blob=>$blob_aad_ok, pepper=>$pepper, aad=>$aad_ok);
    Test::More::ok(!$err_dec_aad_ok && $pt_aad_ok eq $plain, "7b. Decryption with correct AAD succeeds");
    
    my ($pt_aad_wrong, $err_dec_aad_wrong) = $decrypt_ref->(ring_object=>$ring, ciphertext_blob=>$blob_aad_ok, pepper=>$pepper, aad=>$aad_wrong);
    Test::More::ok(defined $err_dec_aad_wrong && $err_dec_aad_wrong eq ERR_DECRYPTION_FAILED, "8. Decryption with wrong AAD fails");

    # Test 9: Decryption fails with wrong pepper
    my $wrong_pepper = random_bytes(PEPPER_LEN);
    while ($wrong_pepper eq $pepper) { $wrong_pepper = random_bytes(PEPPER_LEN); } # Ensure it's different
    my ($pt_wrong_pep, $err_dec_wrong_pep) = $decrypt_ref->(ring_object=>$ring, ciphertext_blob=>$blob1, pepper=>$wrong_pepper, aad=>$aad_ok);
    Test::More::ok(defined $err_dec_wrong_pep && $err_dec_wrong_pep eq ERR_DECRYPTION_FAILED, '9. decryption fails with wrong pepper');

    Test::More::done_testing();
};

#-----------------------------------------------------------------------
#  CLI harness - UPDATED for new error handling
#-----------------------------------------------------------------------
$_cli_demo_ref = sub {
    #my $master_secret = random_bytes(MASTER_SECRET_LEN);
    #my ($ring, $err_build) = $build_cipher_ring_ref->($master_secret);
    #if ($err_build) {
    #    say "CLI Demo: CRITICAL - Failed to build ring: $err_build. Aborting demo.";
    #    return;
    #}
    
    my $ring = load_cipher_ring("/tmp/ring.json");

    #save_cipher_ring ($ring, "/tmp/ring.json");

    my $runtime_pepper= random_bytes(PEPPER_LEN);

    ##say "Master Secret (first 16B of ".MASTER_SECRET_LEN."B): " . unpack("H32", substr($master_secret,0,16));
    say "Ring Base MAC Key (first 16B of ".MAC_KEY_LEN."B): " . unpack("H32", substr($ring->{mac_key},0,16));
    say "Runtime Pepper (first 16B of ".PEPPER_LEN."B): " . unpack("H32", substr($runtime_pepper,0,16));
    say "Dynamic Salt Length: " . DYNAMIC_SALT_LEN . " bytes";
    say "Deterministic Component Length: " . DETERMINISTIC_COMPONENT_LEN . " bytes";

    # --- Encryption 1 ---
    my $msg1 = "Attack at dawn! Ivy v2.4: daemon-ready core and consumers.";
    my $aad1 = "Operation IvyLeaf v2.4";
    say "\n--- Encryption 1 ---";
    say "AAD 1           : $aad1";
    say "Original 1      : $msg1";
    
    my ($blob1, $err_enc1) = $encrypt_ref->(ring_object=>$ring, plaintext=>$msg1, pepper=>$runtime_pepper, aad=>$aad1);
    if ($err_enc1) {
        say "Encryption 1 FAILED: $err_enc1";
    } else {
        my $salt1 = substr($blob1, 0, DYNAMIC_SALT_LEN); 
        say "Dynamic Salt 1 (first 16B of ".DYNAMIC_SALT_LEN."B): ". unpack("H32", substr($salt1,0,16));
        say "Ciphertext 1 (salt+nonce+ct+tag, first 32B): " . unpack("H64", substr($blob1,0,32));
        
        my ($out1, $err_dec1)  = $decrypt_ref->(ring_object=>$ring, ciphertext_blob=>$blob1, pepper=>$runtime_pepper, aad=>$aad1);
        if ($err_dec1) {
            say "Decryption 1 FAILED: $err_dec1";
            say "Recovered 1     : [DECRYPTION FAILED]";
        } else {
            say "Recovered 1     : $out1 " . ($out1 eq $msg1 ? "[OK]" : "[FAIL - PLAINTEXT MISMATCH]");
        }
    }

    # --- Encryption 2 (same message, different salt, different AAD, same pepper) ---
    my $aad2 = "Operation GreenThorn v2.4";
    say "\n--- Encryption 2 (same message, different salt & AAD, same pepper) ---";
    say "AAD 2           : $aad2";
    say "Original 2      : $msg1"; # Using $msg1 for original text

    my ($blob2, $err_enc2) = $encrypt_ref->(ring_object=>$ring, plaintext=>$msg1, pepper=>$runtime_pepper, aad=>$aad2);
    if ($err_enc2) {
        say "Encryption 2 FAILED: $err_enc2";
    } else {
        my $salt2 = substr($blob2, 0, DYNAMIC_SALT_LEN); 
        say "Dynamic Salt 2 (first 16B of ".DYNAMIC_SALT_LEN."B): ". unpack("H32", substr($salt2,0,16));
        say "Ciphertext 2 (first 32B): " . unpack("H64", substr($blob2,0,32));
        
        my ($out2, $err_dec2) = $decrypt_ref->(ring_object=>$ring, ciphertext_blob=>$blob2, pepper=>$runtime_pepper, aad=>$aad2);
        if ($err_dec2) {
            say "Decryption 2 FAILED: $err_dec2";
            say "Recovered 2     : [DECRYPTION FAILED]";
        } else {
            say "Recovered 2     : $out2 " . ($out2 eq $msg1 ? "[OK]" : "[FAIL - PLAINTEXT MISMATCH]");
        }

        if (defined $blob1 && defined $blob2) {
            say "Ciphertext 1 vs 2 different? " . ($blob1 ne $blob2 ? "[YES - GOOD]" : "[NO - BAD]");
            my $s1_demo = substr($blob1, 0, DYNAMIC_SALT_LEN);
            my $s2_demo = substr($blob2, 0, DYNAMIC_SALT_LEN);
            say "Salt 1 vs Salt 2 different?    " . ($s1_demo ne $s2_demo ? "[YES - GOOD]" : "[NO - BAD]");
        }
    }


    # --- Attempt decryption with wrong salt (if blob2 was successfully created) ---
    if (defined $blob1 && defined $blob2) { # Need valid blobs for this test
        say "\n--- Decryption attempt with wrong salt (Salt 1 for Blob 2 data, correct pepper) ---";
        my $salt_from_blob1 = substr($blob1, 0, DYNAMIC_SALT_LEN);
        my $nonce_tag_ct_from_blob2 = substr($blob2, DYNAMIC_SALT_LEN); 
        my $malformed_blob_for_test = $salt_from_blob1 . $nonce_tag_ct_from_blob2;
        
        my ($failed_out_ws, $err_ws) = $decrypt_ref->(ring_object=>$ring, ciphertext_blob=>$malformed_blob_for_test, pepper=>$runtime_pepper, aad=>$aad2); # aad2 matches blob2's original aad
        if ($err_ws) {
            say "Decryption failed as expected: $err_ws";
            say "[OK - FAILED AS EXPECTED]";
        } else {
            say "Recovered (WRONG SALT): $failed_out_ws [UNEXPECTED SUCCESS - THIS IS BAD]";
        }
    } else {
        say "\n--- Skipped decryption attempt with wrong salt (due to earlier encryption failure) ---";
    }

    # --- Attempt decryption with wrong AAD (if blob1 was successfully created) ---
    if (defined $blob1) {
        say "\n--- Decryption attempt with wrong AAD (Blob 1 data with AAD 2, correct pepper) ---";
        my ($failed_out_wa, $err_wa) = $decrypt_ref->(ring_object=>$ring, ciphertext_blob=>$blob1, pepper=>$runtime_pepper, aad=>$aad2); # aad2 is wrong for blob1
        if ($err_wa) {
            say "Decryption failed as expected: $err_wa";
            say "[OK - FAILED AS EXPECTED]";
        } else {
            say "Recovered (WRONG AAD): $failed_out_wa [UNEXPECTED SUCCESS - THIS IS BAD]";
        }
    } else {
        say "\n--- Skipped decryption attempt with wrong AAD (due to earlier encryption failure) ---";
    }
        

    # --- Attempt decryption with wrong PEPPER (if blob1 was successfully created) ---
    if (defined $blob1) {
        say "\n--- Decryption attempt with wrong PEPPER (Blob 1 data, correct AAD, wrong pepper) ---";
        my $wrong_pepper_demo = random_bytes(PEPPER_LEN);
        while ($wrong_pepper_demo eq $runtime_pepper) { $wrong_pepper_demo = random_bytes(PEPPER_LEN); }
        
        my ($failed_out_wp, $err_wp) = $decrypt_ref->(ring_object=>$ring, ciphertext_blob=>$blob1, pepper=>$wrong_pepper_demo, aad=>$aad1); # aad1 is correct for blob1
        if ($err_wp) {
            say "Decryption failed as expected: $err_wp";
            say "[OK - FAILED AS EXPECTED]";
        } else {
            say "Recovered (WRONG PEPPER): $failed_out_wp [UNEXPECTED SUCCESS - THIS IS BAD]";
        }
    } else {
        say "\n--- Skipped decryption attempt with wrong PEPPER (due to earlier encryption failure) ---";
    }
};

use JSON::MaybeXS qw(encode_json decode_json);
use MIME::Base64 qw(encode_base64 decode_base64);
use Scalar::Util qw(refaddr);

#––– Export the ring to a file ––––––––––––––––––––––––––––––––––––––––––––––
sub save_cipher_ring {
    my ($ring, $filename) = @_;
    my %seen;
    my @nodes_export;
    my $node = $ring->{first_node};

    while (refaddr($node) && !$seen{refaddr($node)}++) {
        my %d = $node->();   # index, stored_byte, mac, mode, param, next_node
        push @nodes_export, {
            index       => $d{index},
            stored_byte => $d{stored_byte},
            mac         => encode_base64($d{mac},   ''),  # binary→ascii
            mode        => $d{mode},
            param       => $d{param},
        };
        $node = $d{next_node};
    }

    my $out = {
        mac_key => encode_base64($ring->{mac_key}, ''),
        nodes   => \@nodes_export,
    };

    open my $fh, '>', $filename
      or croak "save_cipher_ring: cannot open '$filename': $!";
    print $fh encode_json($out);
    close $fh;
}

#––– Rebuild the ring from disk ––––––––––––––––––––––––––––––––––––––––––––––
sub load_cipher_ring {
    my ($filename) = @_;
    open my $fh, '<', $filename
      or croak "load_cipher_ring: cannot open '$filename': $!";
    local $/;
    my $json = <$fh>;
    close $fh;

    my $in = decode_json($json);
    my @nodes_data = @{ $in->{nodes} };
    my @closures;
    my @next_refs;

    for my $nd (@nodes_data) {
        my ($i, $sb, $mac_b64, $mode, $param)
          = @{$nd}{qw/index stored_byte mac mode param/};

        my $mac = decode_base64($mac_b64);
        my $next;
        push @next_refs, \$next;

        push @closures, sub {
            return (
                index       => $i,
                stored_byte => $sb,
                mac         => $mac,
                mode        => $mode,
                param       => $param,
                next_node   => $next,
            );
        };
    }

    # link the closures into a ring
    for my $i (0 .. $#closures) {
        ${ $next_refs[$i] } = $closures[ ($i+1) % @closures ];
    }

    my $ring = {
        first_node => $closures[0],
        mac_key    => decode_base64($in->{mac_key}),
    };
    return $ring;
}

#-----------------------------------------------------------------------
#  Program entry‑point
#-----------------------------------------------------------------------
if (@ARGV && $ARGV[0] eq '--test') {
    $_selftest_replan_ref->();
} else {
    $_cli_demo_ref->();
}
