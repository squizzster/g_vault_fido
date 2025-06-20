package enter_master_password;

use strict;
use warnings;
use Term::ReadKey;
use Crypt::Digest::BLAKE2b_256 qw(blake2b_256);
use Crypt::Argon2 qw/argon2id_raw/;
use Crypt::KeyDerivation;

use Exporter 'import';
our @EXPORT_OK = qw(get_master_key);


#   We configure crypto-graphically random *fixed* tags which we'll utilize later....
#   These are not sensitive however people are even beginning to create rainbow-Argon tables now!
#   Overall, they are unique to our application so our final passwords are unique to only us - nobody else!
use constant {
    HKDF_SALT             => pack("H*", 'd06c88296cc2a815ece6788cf2da700b'),
    PASSWORD_TAG          => pack("H*", '2294aa1e1187b79ea5f772d8d58221d1'),
    VAULT_TAG             => pack("H*", 'dd3d274c7c90a66558427136d0db60a6'),
    VERSION               => 'V1.0',
};


sub get_master_key {
    # 1. Locked-in Argon2id parameters. We fix as different params = different key = OMG! later!
    my $i = 8192; # iterations, x 8192
    my $m = 64;   # memory,     = 64mb
    my $c = 1;    # cpu,        = 1

    # 2. Parse vault and password from STDIN if available
    my ($vault_name, $plain_password);
    my $is_stdin_tty = -t STDIN;

    if (!$is_stdin_tty) {
        my $line = <STDIN>;
        chomp($line);
        if ($line =~ /:/) {
            ($vault_name, $plain_password) = split(/:/, $line, 2);
            if (!defined $vault_name || $vault_name eq '' || $vault_name =~ /:/) {
                die "Invalid vault name: cannot be empty or contain ':'\n";
            }
        } else {
            $vault_name = 'default';
            $plain_password   = $line;
        }
        print STDERR "Using vault: $vault_name (input from STDIN)\n";
    }

    # 3. Prompt for vault name if not provided
    if (!defined $vault_name) {
        print STDERR "Vault name (press Enter for 'default'): ";
        chomp($vault_name = <STDIN>);
        $vault_name = 'default' if $vault_name eq '';
        die "Invalid vault name: cannot contain ':'\n" if $vault_name =~ /:/;
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

    # 5. Feed Argon...
    #    We could, but we don't want to feed argon just a '$plain_password' as well that could be 'password', so we always feed an entirely derived hash.

    my $feed_argon_password = blake2b_256(PASSWORD_TAG . $plain_password);
    #    we could, but we don't want to feed argon just a 'plain_vault_name' so again we derive..

    my $feed_argon_salt     = blake2b_256(VAULT_TAG    . $vault_name); 
    # 6. Argon2id derivation (32-byte key)

    ## lower memory for lower memory edge devices but iterations is high
    my $argon_raw_output = argon2id_raw( 
        $feed_argon_password, $feed_argon_salt,
        $i, $m * 1024, $c, 32
    );

    #  hkdf salt is 'TAG + everything' but *NOT* argon_raw_output (or VERSION)
    my $hkdf_salt = blake2b_256(HKDF_SALT . $vault_name . $plain_password . $feed_argon_password . $feed_argon_salt); 

    # 8. Final key derivation, which is argon_raw_output + hkdf_salt + version_label.
    my $password = Crypt::KeyDerivation::hkdf($argon_raw_output, $hkdf_salt, 'BLAKE2b_256', 32, VERSION);
    return unpack("H*", $password);

    # 10.
    # so if a user's password is actually "password"... with a vault name of 'default'
    # we store in DB => '33cec1e9f081a8328f61bfe5dc9900e3d32ded2d8ac53052571dd18401a1d738',
    # and this is deterministic.
}

1;

