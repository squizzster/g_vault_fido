sub rings_equal {
    my ($r1, $r2) = @_;
    return 0
        unless $r1->{name_hash} eq $r2->{name_hash}
            && $r1->{mac_key} eq $r2->{mac_key};

    my $n1 = $r1->{first_node};
    my $n2 = $r2->{first_node};

    do {
        my %a = $n1->();
        my %b = $n2->();
        return 0
            unless $a{index} == $b{index}
                && $a{stored_byte} == $b{stored_byte}
                && $a{mode} eq $b{mode}
                && (   (!defined $a{param} && !defined $b{param})
                    || $a{param} eq $b{param});

        $n1 = $a{next_node};
        $n2 = $b{next_node};
    } while ( refaddr($n1) != refaddr($r1->{first_node}) );

    return 1;
}
1;
