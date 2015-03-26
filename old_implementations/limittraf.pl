#!/usr/bin/perl
###############################################################################
# limittraf (old implementation) - per-client outgoing traffic limiter.
# Copyright (C) 2013 Edward Chernenko.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
###############################################################################

use strict;
use Data::Dumper;

# For what intervals of time (in seconds) do we need per-client statistics?
our @CHAINS = (10, 60, 300,
	3600, # 1 hour
	86400 # 1 day
);
our $ANALYZE_INTERVAL = 1; # seconds (integer)

open(F, "tcpdump -i eth0 -fn -v src port 80 -c 10000 |") || die $!;

my %P = (); # { client_ip1 => [ [ package1length, package1timestamp ], [ package2length, package2timestamp ], ... ] }
my %P24 = (); # { client_subnet1 => ..., client_subnet2 => } for /24 subnets
my %P16 = (); # for /16 subnets

my $last_analyze = time();
my $n = 1;
while(<F>)
{
#	print STDERR "\r$n..." if(!($n % 100));
	$n ++;

	my $time = time(); # Why bother parsing the timestamp? Difference less than 1 second is acceptable.
	my ($length, $ip) = ($_ =~ /length ([0-9]+).*> ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/);
	warn "IP not recognized, do you use IPv6? '$_'\n", next
 		unless($ip);
	
	$P{$ip} = [] unless(exists $P{$ip});
	
	do_register($ip, $length, $time);

	if($time - $last_analyze > $ANALYZE_INTERVAL)
	{
		$last_analyze = $time;
		do_analyze($time); # this won't take long, so we need not call time() again
	}
}
close F;
print STDERR "\r" . (" " x 40) . "\n";

sub do_register
{
	my($ip, $length, $time) = @_;
	
	my @i = split /\./, $ip;	
	my $ip16 = "$i[0].$i[1].0.0/16";
	my $ip24 = "$i[0].$i[1].$i[2].0/24";
	
	$P{$ip} = [] unless(exists $P{$ip});
	$P24{$ip24} = [] unless(exists $P24{$ip24});
	$P16{$ip16} = [] unless(exists $P16{$ip16});
	
	push @{$P{$ip}}, [ $length, $time ];
	push @{$P24{$ip24}}, [ $length, $time ];
	push @{$P16{$ip16}}, [ $length, $time ];
}

sub do_analyze
{
	my $time = shift;
	
	my $interval = 120;

	#
	# TEST function.
	#
	# For each client (or subnet - NYI) we calculate outgoing traffic to them
	# in the last $interval seconds
	#
	
	my %traffic_per_interval_and_ip = ();
	foreach my $ip(keys %P)
	{	
		my $traffic = 0;
		my $packets = $P{$ip}; 
	
		my $idx = $#$packets;
		
		# TODO: track all intervals from @CHAINS
		
		my $interval_start = $time - $interval;
		
		while($idx -- >= 0 && $packets->[$idx][1] >= $interval_start)
		{
			$traffic += $packets->[$idx][0];
		}
		$traffic_per_interval_and_ip{$interval}->{$ip} = $traffic;
	}
	
	print "\033[2J"; # clear the screen
	print "\033[0;0H"; # jump to 0,0

	print "Most traffic-consuming clients in $interval seconds:\n";
	my $h = $traffic_per_interval_and_ip{$interval};
	my @keys = sort { $h->{$b} - $h->{$a} } keys(%$h);
	
	@keys = @keys[0..19]
		if($#keys > 19);
	foreach my $c(@keys)
	{
		print $c . " | " .  ($h->{$c}/1024) . "Kb\n";
	}
	
	# BUG: traffic for some ips goes lower before the $interval from the beginning of the test
	
	print "----------------\n";
}

__END__






print "Most traffic-consuming clients in 10000 packets:\n";
@keys = sort { $TRAFFIC_PER_CLIENT{$b} - $TRAFFIC_PER_CLIENT{$a} } keys(%TRAFFIC_PER_CLIENT);
foreach $c(@keys)
{
	print $c . " | " .  ($TRAFFIC_PER_CLIENT{$c}/1024) . "Kb\n";
}
