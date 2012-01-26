#!/usr/bin/env perl

use warnings;
use strict;

use Net::DNS;
use Getopt::Long;

use constant WHOIS_CACHE_FILE => "~/.whois_org_cache";

# Control newline (\n) output
$\ = '';

# Globals
my $whois_cache = {};

# Default settings, toggled with command line flags
my $options = {
    'no_cache' => 0,
};

exit main();

sub main {
    GetOptions(
        "n|no-cache" => \$main::options->{'no_cache'},
    );

    # Parse request.  Determine if it is a subdomain or not
    my $request = $ARGV[0];

    if ( !$request ) {
        print "Usage: domain_info.pl <domain>\n"
            . "optional flag: -n (or --no-cache) for no organization caching\n\n";
        return (0);
    }

    # Squash any protocol/path information, if present
    $request =~ s/.*:\/\/([^\/]*).*/$1/;

    my $root_domain = get_root_domain($request);

    # If domain isn't the raw domain or www, treat it as custom subdomain
    my $custom_subdomain;

    if ( $request !~ /^(?:$root_domain)|(?:www\.$root_domain)$/ ) {
        $custom_subdomain = $request;
    }

    if ( !$main::options{'no_cache'} ) {
        initialize_whois_cache();
    }

    my $request_info = {
        'domain'           => $root_domain,
        'custom_subdomain' => $custom_subdomain,
        'dns'              => {},
    };

    display_whois_data($root_domain);
    display_dns($request_info);
    display_mx($root_domain);

    print "\n";

    if ( !$main::options{'no_cache'} ) {
        save_whois_cache();
    }

    return (1);
}

sub display_whois_data {
    my $domain = shift;

    if ( !$domain ) {
        die("Internal error: display_whois_data");
    }

    my ( $registrar, @nameservers, @status, $expiration );

    my @whois;
    my $whois_long;
    my $no_match = 0;

    @whois = `whois $domain`;

    foreach my $line (@whois) {
        if ( $line =~ /^\s*No match.*$domain/i || $line =~ /^NOT FOUND/ ) {
            $no_match = 1;
            last;
        }

        if ( $line =~ /Registrar(?: Name)?:\s*(.*)$/i ) {
            $registrar = $1;
        }

        if ( $line =~ /Name\s*Servers?:\s*(.*)$/i ) {
            push( @nameservers, $1 ) unless ( $1 =~ /^\s*$/ );
        }

        if ( $line =~ /Status:\s*(.*)$/i ) {
            push( @status, $1 ) unless ( $1 =~ /^\s*$/ );
        }

        if ( $line =~ /Expiration Date:\s*(.*)$/i ) {
            $expiration = $1;
        }
    }

    if (!@whois) {
        print "No WHOIS information returned.  Is the 'whois' command installed?\n\n";
    }
    elsif ($no_match) {
        print "\n$domain doesn't appear to be registered.\n\n";
        exit(1);
    }
    elsif ( !$registrar && !$expiration ) {
        print "\n$domain: Couldn't parse WHOIS information, or domain may not be registered.\n";
        print "Displaying full WHOIS:\n\n";
        print @whois;
    }
    else {
        print "\n$domain\n\n";

        print "*** Condensed WHOIS information ***\n";
        print "Registrar: $registrar\n";
        print "Expires: $expiration\n" unless ( !$expiration );

        foreach (@status) {
            print "Status: $_\n";
        }

        print "Name servers:\n";
        foreach (@nameservers) {
            print "\t$_\n";
        }
    }
}

sub display_dns {
    my $request_info = shift;

    if ( !$request_info ) {
        die("Internal error: display_dns");
    }

    my $domain           = $request_info->{'domain'};
    my $custom_subdomain = $request_info->{'custom_subdomain'};

    # Determine length of the longest part, to make the domain displays line up
    my $length = 0;

    if ($custom_subdomain) {
        my @tmp = ( 'www.' . $domain, $custom_subdomain );
        @tmp = sort { length $a <=> length $b } @tmp;

        $length = length( $tmp[1] );
    }
    else {
        $length = length( 'www.' . $domain );
    }

    $length += 2;    # Indent output by 2 spaces

    my @domains = ( $domain, 'www.' . $domain );
    push( @domains, $custom_subdomain ) if ($custom_subdomain);

    print "\n\n*** DNS information ***\n";
    print "Web:\n";

    foreach my $display_domain (@domains) {
        printf( "%*s: ", $length, $display_domain );
        display_record( $display_domain, $length );
    }
}

sub display_mx {
    my $domain = shift;
    if ( !$domain ) {
        die("Internal error: display_mx");
    }

    print("\nEmail: \n");

    my $res = Net::DNS::Resolver->new;

    my $length = 0;

    my @mx_results = mx( $res, $domain );
    if (@mx_results) {
        foreach my $mx (@mx_results) {
            my $this_length = length( $mx->exchange );
            $length = $this_length if ( $this_length > $length );
        }

        $length += 1;

        foreach my $mx (@mx_results) {
            printf( "  %2s: %*s: ", $mx->preference, $length, $mx->exchange );
            display_record( $mx->exchange, $length + 6 );
        }
    }
    else {
        print "  No MX records found!\n";
    }
}

sub get_orgname {
    my $ip = shift;

    return 0 if ( !defined($ip) || $ip !~ /(?:\d{1,3}\.){3}\d{1,3}/ );

    # Simple cache per script run, often have many of same IP
    if ( defined( $main::whois_cache->{$ip} ) ) {
        return $main::whois_cache->{$ip}->{'org'};
    }

    my @results = split( /\n/, `whois $ip` );
    my $org = '';

    my $result = '';

    foreach (@results) {
        next if (/^[\s#]|^$|Internet Numbers/ || /^Comment: /);
        $result = $_;

        # Some WHOIS servers use longform
        if (/OrgName:[^\S]*(.*)$/) {
            $org = $1;
            last;
        }

        # Shortform
        # So, we got a line that isn't a comment, blank, or has the generic
        #   'Internet Numbers' entry.  Grab the start of the line, prior to
        #   the last unbroken string of characters before a (
        #
        #   Example of our $result at this point (hopefully):
        #   Google Inc. GOOGLE (NET-74-125-0-0-1) 74.125.0.0 - 74.125.255.255

        if ( !$org && $result =~ /(.*?)(\s*[\w\d\._\-]*\s*)?\(/ ) {
            $org = $1;
            last;
        }
    }

    if ( !$org ) {
        $org = "No organization listed."
    }

    $main::whois_cache->{$ip}->{'org'} = $org;

    return $org;
}

# Thanks, Frank Escobedo!
sub get_root_domain {
    my $domain = shift;

    my @dp = split( /\./, $domain );
    my $num_dp = @dp;

    if ( $domain =~ /\.\w{2,3}\.\w{2}$/ ) {
        if ( $num_dp >= 3 ) {
            return $dp[ $#dp - 2 ] . "." . $dp[ $#dp - 1 ] . "." . $dp[$#dp];
        }
        return 0;
    }
    else {
        return $dp[ $#dp - 1 ] . "." . $dp[$#dp];
    }
}

sub initialize_whois_cache {
    open( CACHE, "<", glob(WHOIS_CACHE_FILE) ) or return;

    foreach my $line (<CACHE>) {
        $line =~ /^([^:]*):([^:]*):(.*)$/;
        my ( $ip, $date, $org ) = ( $1, $2, $3 );

        # date math, remove entries older than a week (60*60*24*7)=604800
        next if ( $date < time() - 604800 );

        $whois_cache->{$ip}->{'org'}  = $org;
        $whois_cache->{$ip}->{'date'} = $date;
    }

    close(CACHE);
}

sub save_whois_cache {
    open( CACHE, ">", glob(WHOIS_CACHE_FILE) ) or die("Could not open whois cache: $!");

    while ( my ( $ip, $ref ) = each(%$main::whois_cache) ) {
        my $org = $ref->{'org'};
        my $date;

        if ( defined( $ref->{'date'} ) ) {
            $date = $ref->{'date'};
        }
        else {
            $date = time();
        }

        print CACHE "$ip:$date:$org\n";
    }

    close(CACHE);
}

sub display_record {
    my $host   = shift;
    my $indent = shift;

    my $res   = Net::DNS::Resolver->new;
    my $query = $res->send($host);

    if ($query) {
        my @answers = $query->answer;
        if ( !@answers ) {
            print("No DNS data found.\n");
            return;
        }

        my $first = 1;

        foreach my $rr (@answers) {
            next unless ( $rr->name eq $host );
            print_node( $rr, \@answers, $indent, $first );
            $first = 0;
        }
    }
    else {
        warn "query failed: ", $res->errorstring, "\n";
    }
}

# Recursive function, follow CNAMEs until we get to an 'A' record
sub print_node {
    my ( $node, $answers, $indent, $is_first ) = @_;
    my $depth = 0;

    if ( scalar @_ == 5 ) {
        $depth = $_[4];
    }

    my $decorator  = '';
    my $indent_mod = 0;

    if ($depth) {
        #We're at least 1 level deep in CNAME resolution

        # Make a pretty arrow
        $decorator = "`-> ";

        # Pad 2 for ': ', and 4 to center under [CNAME], and length of decorator
        $indent_mod = 2 + ( 3 * $depth ) + ( ( $depth > 1 ) ? length($decorator) : 0 );
    }
    elsif ($is_first) {
        # make indent_mod 0 for first result, because we have already
        # output some information on this line (the domain for this DNS result)
        $indent_mod = 0 - $indent;    
    }
    else {
        # This indicates a secondary A or CNAME record defined for a given domain
        $indent_mod = 2;
    }

    if ( $node->type eq "CNAME" ) {
        printf "%*s%s[CNAME] %s\n", $indent + $indent_mod, '', $decorator, $node->cname;

        foreach my $rr (@$answers) {
            next unless ( $rr->name eq $node->cname );
            print_node( $rr, $answers, $indent, 0, $depth + 1 );
        }
    }
    else {
        printf(
            "%*s%s[A] %s (%s)\n",
            $indent + $indent_mod,
            '', $decorator, $node->address, get_orgname( $node->address )
        );
    }
}

