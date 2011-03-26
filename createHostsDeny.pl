#!/usr/bin/perl

# How many hits before we block host?
$threshold = 5;

# How many hits before we block a /24 range?
$rthreshold = 10;

# Deny /24 block? yes = 1; no = 0
$twentyfourDeny = 1;

open DEFAULTDENYFILE, "/etc/hosts.default.deny" or die $!; 
open DENYFILE, ">/etc/hosts.deny" or die $!;


while (<DEFAULTDENYFILE>) {
	print DENYFILE $_;
}

my %ipaddy = ();
my %iprange = ();
$prevIP = "";

@passed = `grep -hE '^P|relay not permitted|Sender verify failed|cherjo|aapublic|rfc-ignorant.org|safe.dnsbl.sorbs.net|zen.spamhaus.org|psbl.surriel.com|bl.spamcop.net' /var/log/exim/reject.* | awk '{print \$4}' | sort`;
@wrapped = `grep -hE 'tcp wrap' /var/log/exim/reject.* | awk '{print \$6}' | sort`;

@total = (@passed,@wrapped);
@total = sort(@total);

foreach $line (@total) {
	chomp $line;
	$line =~ s/\[//g;
	$line =~ s/\]//g;
   	if ($line =~ /^([\d]+)\.([\d]+)\.([\d]+)\.([\d]+)$/) {
		@bits = split(/\./,$line);
		$theTwoFiveFive = $bits[0] . "." . $bits[1] . "." . $bits[2] . ".";
		$curIP = $line;
		if ($ipaddy{$line}) {
			$ipaddy{$line}++;
		} else {
			$ipaddy{$line} = 1;
		}
		if ($curIP ne $prevIP) {
			if ($iprange{$theTwoFiveFive}) {
				$iprange{$theTwoFiveFive}++;
			} else {
				$iprange{$theTwoFiveFive} = 1;
			}
		}	
		$prevIP = $curIP;
   	}
	
}

print DENYFILE "\n";
print DENYFILE "# Spammers\n";

if ($twentyfourDeny == 1) {
	while ( my ($range, $hits) = each(%iprange) ) {
		if ($hits >= $rthreshold) {
        		print DENYFILE "exim: $range\n";
		}
	}
}

while ( my ($addy, $hits) = each(%ipaddy) ) {
	@bits = split(/\./,$addy);
	$theTwoFiveFive = $bits[0] . "." . $bits[1] . "." . $bits[2] . ".";

	if ( ($hits >= $threshold) && !($iprange{$theTwoFiveFive} >= $rthreshold) )  { 
        	print DENYFILE "exim: $addy\n";
	}
}

close DEFAULTDENYFILE;
close DENYFILE;
