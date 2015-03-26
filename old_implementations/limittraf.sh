#!/bin/bash
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

#
# NOTE: this script is slow because of grep/awk invocations (that require forking)
# and unneeded concatenation in $sqlbuffer. Implementation in C is highly preferable.
#

#
# Configuration optionss
#

ltTcpDump=/usr/sbin/tcpdump
ltSqlite=/usr/bin/sqlite3

ltWorkDir=/tmp/limittraf
ltTcpDumpInterface="-i eth0" # leave as "" to track all interfaces
ltAnalyzeInterval=4 # in seconds (integer)

#
# NOTE: can use ltTcpDumpFilter="|grep >" here (catches all outgoing traffic) etc.
#
ltTcpDumpFilter="src port 80"
ltDbFile=sqlite.db


#
# The actual script.
#

sqlite="$ltSqlite $ltDbFile"

function Analyze
{
	echo "Analyzing..."
}

function Begin
{
	mkdir -p $ltWorkDir
	cd $ltWorkDir

	rm -f $ltDbFile
	touch $ltDbFile
	chmod 0600 $ltDbFile

	$sqlite "CREATE TABLE IF NOT EXISTS packet (p_time INTEGER, p_ip TEXT, p_len INTEGER)"
	$sqlite "CREATE TABLE IF NOT EXISTS packet24 (p_time INTEGER, p_ip TEXT, p_len INTEGER)"
	$sqlite "CREATE TABLE IF NOT EXISTS packet16 (p_time INTEGER, p_ip TEXT, p_len INTEGER)"

	last_analyze=`date +'%s'`
	sqlbuffer=""
	
	$ltTcpDump $ltTcpDumpInterface -fnv $ltTcpDumpFilter | \
	while read packet; do

		#
		# Format of $packet:
		# 09:25:26.700057 IP (tos 0x0, ttl 64, id 605, offset 0, flags [DF], proto TCP (6), length 40) 10.242.83.101.http > 10.11.12.13.mqe-broker: ., cksum 0xa1af (correct), ack 2601989226 win 6800
		#
		ip=`echo $packet | grep -oP '(?<=> )[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'`
		test $ip || exit 0 # if we get interrupted by Ctrl+C, the line may be incomplete

		length=`echo $packet | grep -oP '(?<=length )[0-9]+'`
		date=`date +'%s'`
		ip24=`echo $ip | awk -F. '{ print $1.$2.$3.0; }'`
		ip16=`echo $ip | awk -F. '{ print $1.$2.0.0; }'`
		
		# TODO: buffer many INSERTs into one transaction

		sqlbuffer="INSERT INTO packet VALUES($date,'$ip',$length);INSERT INTO packet24 VALUES($date, '$ip24', $length);INSERT INTO packet16 VALUES($date, '$ip16', $length);$sqlbuffer"
		
		if [ $(( $date - $last_analyze )) -gt $ltAnalyzeInterval ]; then		
			Analyze
			last_analyze=`date +'%s'`
		fi
		
		i=$(($i + 1))
		if [ $((i % 100)) -eq 0 ]; then
			echo $i
			
			echo "BEGIN;$sqlbuffer COMMIT;" | $sqlite
			sqlbuffer=
		fi
	done
}

Begin
