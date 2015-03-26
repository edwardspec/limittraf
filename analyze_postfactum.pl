#!/usr/bin/perl
###############################################################################
# limittraf - per-client outgoing traffic limiter.
# Copyright (C) 2013-2015 Edward Chernenko.
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
#
# Scan $dbfile and print statistical distribution of a number of clients by the level of traffic they exceed in $limit_interval.
#

#
# NOTE: 
#	CREATE INDEX packet_time ON packet (p_time);
# makes everything much faster.
#

our $dbfile = 'limittraf.sample.db';
our $limit_interval = 15*60; # 15 minutes
our $analyze_interval = 15; # the increase of $TIME between 2 calculations (in seconds).
our $deltaM = 10240; # 10 kilobytes, the step between keys in distribution function $N{$M} (which is calculated by this script).

use strict;
use Data::Dumper;

use DBI;
my $dbh = DBI->connect("dbi:SQLite:dbname=$dbfile", undef, undef, { RaiseError => 1 });

my $sth = $dbh->prepare('SELECT MIN(p_time), MAX(p_time) FROM packet');
$sth->execute();
our($TIME_START, $TIME_END) = $sth->fetchrow_array;
$sth->finish();

#
# Make sure that there're no "incomplete $analyze_interval invervals".
# 
my $seconds = $TIME_END - $TIME_START;
my $skip_last = $seconds % $analyze_interval;
$TIME_END -= $skip_last;
$seconds -= $skip_last;

#
# Prepare the scanning SQL.
#
my $sth = $dbh->prepare('SELECT p_ip, SUM(p_len) FROM packet WHERE p_time > ? AND p_time < ? GROUP BY p_ip ORDER BY SUM(p_len) DESC');
$sth->execute();

#
# Begin the scan.
#
our $STEPS = $seconds / $analyze_interval;
$TIME_END -= $analyze_interval;

my $step = 1;
my $newtime;

#
#
our %N = (); # distribution of number of users (values) for each [M; M + delta M] inteval (M is the key).
our %SPIKE = (); # maximum spike (values) in $limit_interval for each IP encountered (keys).


for(my $TIME = $TIME_START; $TIME < $TIME_END; $TIME += $analyze_interval, $step ++)
{
	print STDERR sprintf('%-5i/%5i', $step, $STEPS) . "\n";

	$sth->execute($TIME, $TIME + $limit_interval);
	while(my($ip, $len) = $sth->fetchrow_array)
	{
		my $M = $len - $len % $deltaM; # scale down
		
		if(exists $SPIKE{$ip}) # This IP has already exceeded the limit
		{
			if($SPIKE{$ip} < $M)
			{
				$N{$SPIKE{$ip}} --;
				$SPIKE{$ip} = $M;
				$N{$M} ++;
			}
		}
		else # We see this IP the first time
		{
			$SPIKE{$ip} = $M;
			$N{$M} ++;
		}
	}
}

foreach my $M(sort { $a - $b } keys %N)
{
	print "$M,$N{$M}\n";
}
