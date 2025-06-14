package b58f;
use strict;
use warnings;
use Crypt::Misc ();

sub encode { my ($bytes) = @_; $bytes ? Crypt::Misc::encode_b58f($bytes) : undef }
sub decode { my ($str  ) = @_; $str   ? Crypt::Misc::decode_b58f($str  ) : undef }

1;
