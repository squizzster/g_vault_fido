sub pid_walk_back {
  my ($pid, $auth_pid) = @_;
  return undef unless defined $pid && defined $auth_pid;
  return undef unless $pid =~ /^\d+$/ && $auth_pid =~ /^\d+$/;
  return undef if $pid < 1 || $auth_pid < 1;

  $> = 0;  # become root if possible

  while (1) {
    return 1 if $pid == $auth_pid;

    return 0 if $pid == 1;  # reached init without match

    my $path = "/proc/$pid/stat";
    open my $fh, '<', $path or do {
      return undef;
    };

    local $/ = undef;
    my $stat_raw = <$fh>;
    close $fh;

    my @stat = $stat_raw =~ /(?<=\().*(?=\))|[^\s()]+/gs;
    unless (@stat >= 4 && $stat[3] =~ /^\d+$/) {
      return undef;
    }

    my $ppid = int($stat[3]);
    return 0 if $ppid == 0 || $ppid == $pid;  # prevent loop or corrupt ppid

    $pid = $ppid;
  }
}

use Data::Dump qw(dump);
my $ok = pid_walk_back ( 551962, 1 );
print "OK was " . ( dump $ok );
print "\n";
