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

open(F, "tcpdump -i eth0 -fn -v src port 80 -c 10000 |") || die $!;

%TRAFFIC_PER_CLIENT = ();
$TRAFFIC_PER_CLIENT{TOTAL} = 0;

$n = 1;
while(<F>)
{
	print STDERR "\r$n..." if(!($n % 100));

	($length, $client) = ($_ =~ /length ([0-9]+).*> ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/);
#	print $client . " | " . $length . "\n";
	
	$TRAFFIC_PER_CLIENT{$client} = 0
		if(!exists $TRAFFIC_PER_CLIENT{$client});
	$TRAFFIC_PER_CLIENT{$client} += $length;
	$TRAFFIC_PER_CLIENT{TOTAL} += $length;
	
	$n ++;
}
close F;
print STDERR "\r" . (" " x 40) . "\n";

print "Most traffic-consuming clients in 10000 packets:\n";
@keys = sort { $TRAFFIC_PER_CLIENT{$b} - $TRAFFIC_PER_CLIENT{$a} } keys(%TRAFFIC_PER_CLIENT);
foreach $c(@keys)
{
	print $c . " | " .  ($TRAFFIC_PER_CLIENT{$c}/1024) . "Kb\n";
}
