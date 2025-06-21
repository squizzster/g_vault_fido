package enter_master_password;

use strict;
use warnings;
use Term::ReadKey;
use Crypt::Digest::BLAKE2b_256 qw(blake2b_256);
use Crypt::Argon2 qw/argon2id_raw/;
use Crypt::KeyDerivation;

use Exporter 'import';
our @EXPORT_OK = qw(get_master_key);

#   We configure cryptographically random *fixed* tags which we'll utilize for domain separation.
#   These are not specifically sensitive but they are not public knowledge either!
#   People would need to access the source-code to determine which would already be bad!
#   Overall, they are unique to our application so our final master keys are unique to only us - nobody else!

use constant {
    HKDF_DOMAIN_SEP        => pack("H*", 'd06c88296cc2a815ece6788cf2da700b'),
    PASSWORD_DOMAIN_SEP    => pack("H*", '2294aa1e1187b79ea5f772d8d58221d1'),
    VAULT_DOMAIN_SEP       => pack("H*", 'dd3d274c7c90a66558427136d0db60a6'),
    VERSION                => 'V1.0',
};

sub get_master_key {
    # 1. Locked-in Argon2id parameters. We fix as different params = different key = OMG! later!
    my $t_cost = 8192; # time cost (iterations)
    my $m_cost = 64;   # memory,     = 64mb
    my $p_cost = 1;    # parallelism = 1

    # 2. Parse vault and password from STDIN if available
    my ($vault_namespace, $plain_password);
    my $is_stdin_tty = -t STDIN;

    if (!$is_stdin_tty) {
        my $line = <STDIN>;
        chomp($line);
        if ($line =~ /:/) {
            ($vault_namespace, $plain_password) = split(/:/, $line, 2);
            if (!defined $vault_namespace || $vault_namespace eq '' || $vault_namespace =~ /:/) {
                die "Invalid vault name: cannot be empty or contain ':'\n";
            }
        } else {
            $vault_namespace = 'default';
            $plain_password   = $line;
        }
        print STDERR "Using vault: $vault_namespace (input from STDIN)\n";
    }

    # 3. Prompt for vault name if not provided
    if (!defined $vault_namespace) {
        print STDERR "Vault name (press Enter for 'default'): ";
        chomp($vault_namespace = <STDIN>);
        $vault_namespace = 'default' if $vault_namespace eq '';
        die "Invalid vault name: cannot contain ':'\n" if $vault_namespace =~ /:/;
    }

    # 4. Prompt for password interactively (if not from STDIN)
    if (!defined $plain_password) {
        my ($verify, $third_confirm);
        while (1) {
            Term::ReadKey::ReadMode('noecho');
            print STDERR "\nEnter master password: ";
            chomp($plain_password = Term::ReadKey::ReadLine(0));
            print STDERR "\nRe-enter your password: ";
            chomp($verify = Term::ReadKey::ReadLine(0));
            Term::ReadKey::ReadMode('restore');
            print STDERR "\n";

            if (!defined($plain_password) || !defined($verify)) {
                print STDERR "Password input error.\n";
                next;
            }

            if ($plain_password ne '' && $plain_password eq $verify) {
                last;
            }

            if ($plain_password eq '' && $verify eq '') {
                print STDERR "You entered a blank password. Confirm this is intentional.\n";
                Term::ReadKey::ReadMode('noecho');
                print STDERR "Re-enter a blank password to confirm: ";
                chomp($third_confirm = Term::ReadKey::ReadLine(0));
                Term::ReadKey::ReadMode('restore');
                print STDERR "\n";
                if ($third_confirm eq '') {
                    last;
                } else {
                    print STDERR "Blank password not confirmed. Try again.\n";
                    next;
                }
            }

            print STDERR "Passwords must match. Try again.\n";
        }
    }

    # 5. Domain-separated derivation before Argon2id:
    #    We never feed Argon2id a raw password or vault name; instead, we always domain-separate and hash them.

    my $argon2id_password = blake2b_256(PASSWORD_DOMAIN_SEP . $plain_password);
    my $argon2id_context  = blake2b_256(VAULT_DOMAIN_SEP    . $vault_namespace);

    # 6. Argon2id derivation (32-byte key)
    my $argon2id_out = argon2id_raw(
        $argon2id_password, $argon2id_context,
        $t_cost, $m_cost * 1024, $p_cost, 32
    );

    # 7. HKDF "salt" is really a further domain-separated context for the final HKDF step
    my $hkdf_context = blake2b_256(HKDF_DOMAIN_SEP . $vault_namespace . $argon2id_password . $argon2id_context);

    # 8. Final key derivation, which is argon2id_out + hkdf_context + version label.
    my $master_key = Crypt::KeyDerivation::hkdf($argon2id_out, $hkdf_context, 'BLAKE2b_256', 32, VERSION);
    return ($vault_namespace, unpack("H*", $master_key));

    # NOTES:
    # The final derived key must "collide" with itself deterministically. That’s not a flaw — that’s the point.
    # Anyone using the same password and vault name gets the same final key.
    # We are not seeking hash collisions — we are seeking identity preservation:
    # The final key is the key to another system... it is deterministic but cryptographically random.
}

1;
