#!/usr/bin/env perl

use strict;

use Socket;
use Net::DNS;
use Getopt::Long;

use constant WHOIS_CACHE_FILE => "~/.whois_org_cache";

# Control newline (\n) output
$\ = '';

my $no_cache = 0;
my $debug = 0;

GetOptions(
    "d|debug"       => \$debug, 
    "n|no-cache"    => \$no_cache,
);

my $domain = $ARGV[0];
my $raw_domain = get_raw_domain($domain);

if ( !$domain ) {
    print "Usage: domain_info.pl <domain>\n" .
          "optional flags: -n for no organization caching, -d for debug\n\n";
    exit(0);
}

# Global for caching orgname's for IP
my $whois_cache = {};
if ( !$no_cache ) {
    initialize_whois_cache();
}

my ($registrar, @nameservers, @status, $expiration);

my @whois;
my $whois_long;
my $no_match = 0;

# Capture useful info from whois
if ( $domain =~ /\.co\.uk$/ ) { 
    $/ = '';
    my $whois_long = `whois $raw_domain`;
    my $nameservers;

    if ( $whois_long =~ /^\s*This domain name has not been registered./m ) {
        $no_match = 1;
    } else {
        if ( $whois_long =~ /Registrar:\s*(.*)$/m ) {
            $registrar = $1;
        }
        
        if ( $whois_long =~ /Name servers:\s*(.*)\s+(?:WHOIS)/ ) {
            $nameservers = $1;
        }
   
        print "DBG: registrar = '$registrar'\n";
        print "DBG: nameserver = '$nameservers'\n";
    }
} else {
    @whois = `whois $raw_domain`;

    foreach my $line (@whois) {
        if ( $line =~ /^\s*No match.*$domain/i ) {
            print ($line . "\n");
            $no_match = 1;
            last;
        }
        
        if ( $line =~ /Registrar(?: Name)?:\s*(.*)$/i ) {
            $registrar = $1;
        }
    
        if ( $line =~ /Name\s*Servers?:\s*(.*)$/i ) {
            push(@nameservers, $1) unless ( $1 =~ /^\s*$/ );
        }
    
        if ( $line =~ /Status:\s*(.*)$/i ) {
            push (@status, $1) unless ( $1 =~ /^\s*$/ );
        }
        
        if ( $line =~ /Expiration Date:\s*(.*)$/i ) {
            $expiration = $1;
        }
    }
}

if ( $no_match ) {
    print "\n$domain doesn't appear to be registered.\n\n";
    exit(1);
}

if (!$registrar && !$expiration) {
    print "\n$domain: Couldn't parse WHOIS information, or domain may not be registered.\n";
    print "Displaying full WHOIS:\n\n";
    print @whois;
} else {
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

# Grab DNS information for domain, www., and email

# If domain isn't the raw domain or www, treat it as custom sub domain
my $custom_sub;

if ( $domain !~ /^(?:$raw_domain)|(?:www\.$raw_domain)$/ ) {
    $custom_sub = $domain;
}

my $dns = check_dns($raw_domain, $custom_sub);

my $length = 0;

if ($custom_sub) {
    my @tmp = ( 'www.' . $raw_domain, $custom_sub );
    @tmp = sort {length $a <=> length $b} @tmp;
    
    $length = length( $tmp[1] );
} else {
    $length = length('www.' . $raw_domain);
}

my @types = ('domain', 'www', 'custom');
my @domains = ($raw_domain, 'www.' . $raw_domain);
push(@domains, $custom_sub) if ( $custom_sub );

print "\n\n*** DNS information ***\n";
print "Web:\n";

for ( my $i = 0; $i < $#domains + 1; $i++ ) {
    my $type = $types[$i];

    if ( defined($dns->{$type}->{'ip'}) && !defined($dns->{$type}->{'error'}) ) {
        printf "%*s: %s (%s)\n", $length + 2, $domains[$i], $dns->{$type}->{'ip'}, $dns->{$type}->{'org'};
    } else {
        printf "%*s: No DNS data found\n", $length + 2, $domains[$i];
    }
}

print "\nEmail:\n";

while (my ($mx, $ref) = each( %{$dns->{'email'}} ) ) {
    if ( $mx =~ /^error$/ ) {
        print "  Error fetching MX records!\n";
    } else {
        print "  MX: $mx = " . $ref->{'ip'} . " (" . $ref->{'org'} . ")\n";
    }
}

print "\n";

if (!$no_cache) {
    save_whois_cache();
}

exit(1);


sub check_dns
{
    my ($domain, $custom_sub) = @_;

    my $results = {};

    # Check raw domain
    $results->{'domain'} = get_dns_info($domain);

    # Check www version
    $results->{'www'} = get_dns_info("www.$domain");
    
    # Check if someone specified a subdomain
    if ( $custom_sub ) {
        $results->{'custom'} = get_dns_info($custom_sub);
    }
    
    # Check MX
    my $res  = Net::DNS::Resolver->new;
    # Force IPv4 (eval'd due to module versions not containing force_v4)
    eval { 
        $res->force_v4(1);
    };

    my @mx   = mx($res, get_raw_domain($domain));

    if ( @mx ) {
        foreach my $rr ( @mx ) {
            my $mx_record = $rr->exchange;
            $results->{'email'}->{$mx_record} = get_dns_info($mx_record);
        }
    }
    else {
        $results->{'email'}->{'error'} = $res->errorstring;
    }

    return $results;
}


sub get_dns_info
{
    my $host = shift;

    my $ref = {};
    my ($ip, $tmp) = '';
    
    $ref->{'hostname'} = $host;

    if ( defined($tmp = inet_aton($host)) ) {
        $ip = inet_ntoa($tmp);
        $ref->{'ip'} = $ip;
        $ref->{'org'} = get_orgname($ip);
    }
    else {
        $ref->{'error'} = "true";
    }
    
    return $ref;
}


sub get_orgname
{
    my $ip = shift;

    return 0 if ( !defined($ip) || $ip !~ /(?:\d{1,3}\.){3}\d{1,3}/ );

    # Simple cache per script run, often have many of same IP
    if ( defined($whois_cache->{$ip}) ) {
        return $whois_cache->{$ip}->{'org'};
    }

    my @results = split(/\n/, `whois $ip`);
    my $org = '';

    my $result = '';

    foreach (@results) {
        next if ( /^[\s#]|^$|Internet Numbers/ );
        $result = $_;

        # Old way.  Seems to have changed for most TLD in 6/2011
        if ( /OrgName:[^\S]*(.*)$/ ) {
           $org = $1;
           last;
        }

        # New way:
        # So, we got a line that isn't a comment, blank, or has the generic 
        #   'Internet Numbers' entry.  Grab the start of the line, prior to
        #   the last unbroken string of characters before a (
        #
        #   Example of our $result at this point (hopefully):
        #   Google Inc. GOOGLE (NET-74-125-0-0-1) 74.125.0.0 - 74.125.255.255

        if ( $result =~ /(.*?)(\s*[\w\d\._\-]*\s*)?\(/ ) {
            $org = $1;
            last;
        }
    }

    if ( !$org ) {
        $org = "No organization listed."
    }

    $whois_cache->{$ip}->{'org'} = $org;
    
    return $org;
}


# Thanks, Frank Escobedo!
sub get_raw_domain
{
    my $domain = shift;
    my @dp = split( /\./, $domain );
    my $num_dp = @dp;

    if ( $domain =~ /\.\w{2,3}\.\w{2}$/ ) {
        if ( $num_dp >= 3 ) {
            return $dp[ $#dp - 2 ] . "." . $dp[ $#dp - 1 ] . "." . $dp[ $#dp ];
        }
        return 0;
    }
    else {
        return $dp[ $#dp - 1 ] . "." . $dp[ $#dp ];
    }
}


sub initialize_whois_cache
{
    open(CACHE, "<", glob(WHOIS_CACHE_FILE)) or return;
    
    foreach my $line (<CACHE>) {
        $line =~ /^([^:]*):([^:]*):(.*)$/;
        my ($ip, $date, $org) = ($1, $2, $3);
        
        # date math, remove entries older than a week (60*60*24*7)=604800
        next if ( $date < time() - 604800 );

        $whois_cache->{$ip}->{'org'} = $org;
        $whois_cache->{$ip}->{'date'} = $date;
    }
    
    close(CACHE);
}


sub save_whois_cache
{
    open(CACHE, ">", glob(WHOIS_CACHE_FILE)) or die("Could not open whois cache: $!");
    
    while ( my ($ip, $ref) = each(%$whois_cache) ) {
        my $org  = $ref->{'org'};
        my $date;
        
        if ( defined($ref->{'date'}) ) {
            $date = $ref->{'date'};
        }
        else {
            $date = time();
        }
        
        print CACHE "$ip:$date:$org\n";
    }
    
    close (CACHE);
}
