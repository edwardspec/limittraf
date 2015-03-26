/*
	limittraf - per-client outgoing traffic limiter.
	Copyright (C) 2013-2015 Edward Chernenko.

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
*/

/*
	Configuration options
*/

const char *ltCfgFile = "limittraf.conf";

const char *ltTcpDump = "tcpdump"; // "/usr/sbin/tcpdump";
const char *ltNetworkInterface = "em1"; // "eth0"
const char *ltTcpDumpOptions = "src port 80";

const char *ltTc = "tc"; // "/sbin/tc"

const char *ltWorkDir = "/tmp/limittraf";
const char *ltDbFile = "limittraf.db";
const char *ltLogFile = "limittraf.log";
const unsigned long ltLegitimateSearchEngineCacheExpires = 604800; // 604800 seconds = 1 week

const int ltAnalyzeInterval = 5;
const unsigned long ltMemoryDumpLevel = 10 * 1204 * 1024; // 10 megabytes

/*




*/

#include <stdio.h>
#include <pcre.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "conf.h"
#include "database.h"
#include "legsearch.h"
#include "actions.h"

/*
	Format of two lines printed by 'tcpdump -fnvKtq', with the newline removed from the first line:
		IP (tos 0x0, ttl 64, id 46394, offset 0, flags [DF], proto TCP (6), length 1492)    10.205.15.60.80 > 80.102.204.74.1155: tcp 1452
*/
static const char TcpDumpRequiredParams[] = "-fnvKtq"; /* These affect the format and therefore must be specified for parsing to success */

static const char TCPDUMP_REGEX[] = "length ([0-9]+).*> ([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)";
static const int TCPDUMP_LINE_MAX = 4096;

static pcre *tcpdump_regex;
static pcre_extra *tcpdump_extra;

time_t TIME = 0; /* = time(NULL), an approximation for timestamp of current packet */


/* ... */
static void Initialize(); /* Create the database and compile the regex */
static void Analyze(); /* Called every ltAnalyzeInterval seconds */

int main( void )
{
	char buffer[TCPDUMP_LINE_MAX];
	int ovector[9]; /* we have 2 values to match, +1 place for the entire regexp; PCRE requires 3x more space */
	char *TcpDumpCommand;
	FILE *tcpdump;
	int lineno;
	time_t last_analyze;
	int ret;
	
	/* IP and length are determined for each packet */
	char ip[17]; int length;
	char length_as_string[6]; /* MTU is never longer than 5 digits in decimal notation */
	
	Initialize();

#if 0
	const char *testhost =
 		"66.249.73.111"
		// "199.21.99.124"
		;
	fprintf(stderr, "%s is%s a legitimate search engine\n", testhost, is_legitimate_search_engine(testhost) ? "" : " NOT");
	fprintf(stderr, "%s is%s a legitimate search engine\n", testhost, is_legitimate_search_engine(testhost) ? "" : " NOT");
	fprintf(stderr, "%s is%s a legitimate search engine\n", testhost, is_legitimate_search_engine(testhost) ? "" : " NOT");
	exit(0);
#endif
	
	TcpDumpCommand = malloc(1024);
	if(!TcpDumpCommand)
	{
		fprintf(stderr, "malloc() for TcpDumpCommand failed: %s\n", strerror(errno));
		exit(1);
	}
	snprintf(TcpDumpCommand, 1024, "%s %s %s -i %s", ltTcpDump, ltTcpDumpOptions, TcpDumpRequiredParams, ltNetworkInterface);
	
	fprintf(stderr, "Starting %s\n", TcpDumpCommand);
	tcpdump = popen(TcpDumpCommand, "r");
	if(!tcpdump)
	{
		fprintf(stderr, "popen(%s) failed: %s\n", ltTcpDump, strerror(errno));
		return 1;
	}
	free(TcpDumpCommand);
	
	/* begin Main Loop */
	lineno = 0;
	last_analyze = time(NULL);
	while(fgets(buffer, TCPDUMP_LINE_MAX, tcpdump))
	{
		int off = strlen(buffer);
#ifndef NDEBUG
		if(!off)
		{
			fprintf(stderr, "tcpdump returned an empty line (bug in tcpdump or changed format). Exiting.\n");
			exit(1);
		}
#endif
		fgets(&buffer[off - 1], TCPDUMP_LINE_MAX - off, tcpdump);
		time(&TIME);

		if((++ lineno) % 100 == 0)
		{
			fprintf(stderr, "%i...\n", lineno);
			if(DbMemoryUsed() > ltMemoryDumpLevel)
			{
				CommitTransaction();
				CompactDb();
				BeginTransaction();
			}
		}
	
		ret = pcre_exec(tcpdump_regex, tcpdump_extra, buffer, strlen(buffer), 0, 0, ovector, 9);
		if(ret < 0)
		{
			fprintf(stderr, "pcre_exec() returned %i on [[%s]]\n", ret, buffer);
			continue;
		}

		pcre_copy_substring(buffer, ovector, 8, 1, length_as_string, 6);
		pcre_copy_substring(buffer, ovector, 8, 2, ip, 17);
		
//		fprintf(stderr, "[%6i] Length %s from %s\n", lineno, length_as_string, ip);
		
		length = atoi(length_as_string);
		Register(ip, length);

		if(TIME - last_analyze > ltAnalyzeInterval)
		{
			last_analyze = TIME;

			/* No error checking on commits because this is our private in-memory database */
			CommitTransaction();
			Analyze();
			BeginTransaction();
		}
	}
	
	return 0;
}

__attribute__((cold)) static void CompileTcpdumpRegex()
{
	const char *error; int erroffset;
	tcpdump_regex = pcre_compile(TCPDUMP_REGEX, PCRE_NO_UTF8_CHECK, &error, &erroffset, NULL);
	if(!tcpdump_regex)
	{
		fprintf(stderr, "Failed to compile regexp: '%s': %s\n", TCPDUMP_REGEX, error);
		exit(1);
	}
	tcpdump_extra = pcre_study(tcpdump_regex, PCRE_STUDY_JIT_COMPILE, &error); /* returned NULL is ok here */
}

__attribute__((cold)) static void Initialize()
{
	ReadConfiguration(ltCfgFile);
	
	if(mkdir(ltWorkDir, 0700) < 0 && errno != EEXIST)
	{
		fprintf(stderr, "mkdir(%s) failed: %s\n", ltWorkDir, strerror(errno));
		exit(1);
	}
	chdir(ltWorkDir);
	
	CompileTcpdumpRegex();
	InitializeLegSearch();
	InitializeActions();
	InitializeDb();
}
__attribute__((cold)) static void Terminate()
{
	TerminateDb();
	TerminateActions();
	TerminateLegSearch();
	if(tcpdump_extra) pcre_free_study(tcpdump_extra);
}

/**


*/
__attribute__((hot)) static void Analyze()
{
	fprintf(stderr, "Analyzing...\n");
	
	AnalyzeDb(); /* the actual work is performed here */
	CompactDb();
	LegSearch_Save();
}
