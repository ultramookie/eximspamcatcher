#!/usr/bin/perl

# How many hits before we block host?
$threshold = 5;

open DEFAULTDENYFILE, "/etc/hosts.default.deny" or die $!; 
open DENYFILE, ">/etc/hosts.deny" or die $!;


while (<DEFAULTDENYFILE>) {
	print DENYFILE $_;
}

my %ipaddy = ();

@passed = `grep -hE '^P' /var/log/exim/reject.* | awk '{print \$4}' | sort`;

foreach $line (@passed) {
	chomp $line;
	$line =~ s/\[//g;
	$line =~ s/\]//g;
   	if ($line =~ /^([\d]+)\.([\d]+)\.([\d]+)\.([\d]+)$/) {
		if ($ipaddy{$line}) {
			$ipaddy{$line}++;
		} else {
			$ipaddy{$line} = 1;
		}
   	}
	
}

print DENYFILE "\n";
print DENYFILE "# Spammers\n";

while ( my ($addy, $hits) = each(%ipaddy) ) {
	if ($hits >= $threshold) { 
        	print DENYFILE "exim: $addy\n";
	}
}

close DEFAULTDENYFILE;
close DENYFILE;
