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

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "limittraf.h"
#include "actions.h"
#include "legsearch.h"

static FILE *logfile;
static int logfile_buffered_writes = 0;

/*
	These are the parameters for traffic control classes (for LIMIT).
	bandwidth_limits_unique[] is sorted DESC.
	
	NOTE: bandwidth_limits_unique[0] correspond to classid 1:1,
		[1] to classid 1:2 etc.
*/
static int *bandwidth_limits_unique;
static int class_count; // = number of elements in bandwidth_limits_unique[]

static inline void system_or_fatal(const char *command)
{
	int ret;
	fprintf(stderr, "$ %s\n", command);

	ret = system(command);
	if(ret == -1)
	{
		fprintf(stderr, "system(%s) failed: %s\n", command, strerror(errno));
		exit(1);
	}
	if(ret != 0)
	{
		fprintf(stderr, "ERROR: '%s' failed.\n", command);
		exit(1);
	}
}

__attribute__((cold)) static int compare_ints_desc(const void *a, const void *b)
{
	return *((int *) b) - *((int *) a);
}

/*
	SetupTrafficControl() - create traffic shaping rules for LIMIT.
	
	NOTE: for simplicity we assumed that 'tc' is not yet used by
	this system (we simply recreate the shaping rules from scratch).
	For now this function will print a error and exit if custom
	traffic control is already in use.
*/
static inline void SetupTrafficControl()
{
	FILE *p;
	char command[1024];
	int i, j, k;
	int *bandwidth_limits;
	
	if(PLAN_limit_triggers_count == 0)
	{
		fprintf(stderr, "DEBUG: no LIMIT actions, SetupTrafficControl is skipped\n");
		return;
	}
	
	bandwidth_limits = malloc(sizeof(int) * PLAN_limit_triggers_count);
	if(!bandwidth_limits)
	{
		fprintf(stderr, "malloc() for bandwidth_limits failed: %s\n", strerror(errno));
		exit(1);
	}
	
	snprintf(command, 1024, "%s filter show dev %s", ltTc, ltNetworkInterface);
	p = popen(command, "r");
	if(!p)
	{
		fprintf(stderr, "popen(%s) failed: %s\n", ltTc, strerror(errno));
		exit(1);
	}
	
	/* TODO: detect filters created by the limittraf itself and ignore them */
	
	if(getc(p) != EOF)
	{
		fprintf(stderr, "FATAL:\ttraffic control (tc) filters are already in use!\n\tLIMIT rules in these conditions are not yet implemented.\n");
		exit(1);
	}
	pclose(p);
	
	/* TODO:
		Add an option to allow removal of the existing traffic
		control rules via 'tc qdisc del dev $DEV root'
	*/
	snprintf(command, 1024, "%s qdisc del dev %s root", ltTc, ltNetworkInterface);
	system_or_fatal(command);
	
	snprintf(command, 1024, "%s qdisc add dev %s root handle 1: htb", ltTc, ltNetworkInterface);
	system_or_fatal(command);
	

	/* How many different bandwidth_limit values do we have for LIMIT rules?
		(that goes into 'int class_count')
	*/
	k = 0;
	for(i = 0; i < PLAN.count; i ++)
		for(j = 0; j < PLAN.intervals[i].count; j ++)
			if(PLAN.intervals[i].actions[j].type == LIMITTRAF_ACTION_LIMIT)
				bandwidth_limits[k ++] = PLAN.intervals[i].actions[j].bandwidth_limit;
	class_count = k;

	/*
		Remove all duplicates from bandwidth_limits.
		'k' will become the number of unique values.
	*/
	qsort(bandwidth_limits, PLAN_limit_triggers_count, sizeof(int), compare_ints_desc);
	for(i = 1; i < PLAN_limit_triggers_count; i ++)
		if(bandwidth_limits[i] == bandwidth_limits[i - 1])
			class_count --; /* one unique item less */
	k = class_count;
	
	bandwidth_limits_unique = malloc(sizeof(int) * class_count);
	if(!bandwidth_limits_unique)
	{
		fprintf(stderr, "malloc() for bandwidth_limits_unique failed: %s\n", strerror(errno));
		exit(1);
	}
	
	/* NOTE: bandwidth_limits_unique is sorted DESC too */
	bandwidth_limits_unique[0] = bandwidth_limits[0];
	for(i = 1; i < PLAN_limit_triggers_count; i ++)
	{
		if(bandwidth_limits[i] != bandwidth_limits[i - 1])
			bandwidth_limits_unique[class_count - (-- k)] = bandwidth_limits[i];
	}
	free(bandwidth_limits);
	
#if 1
	fprintf(stderr, "DEBUG: bandwidth_limits_unique[%i] = ", class_count);
	for(i = 0; i < class_count; i ++)
	{
		fprintf(stderr, " %i |", bandwidth_limits_unique[i]);
	}
	fprintf(stderr, "\n");
#endif

	for(i = 0; i < class_count; i ++)
	{
		snprintf(command, 1024, "%s class add dev %s parent 1: classid 1:%i htb rate %li burst 10k mpu 64",
			ltTc, ltNetworkInterface, i + 1, (long) bandwidth_limits_unique[i] * 8);
		system_or_fatal(command);
	}
}


__attribute__((cold)) void InitializeActions()
{
	SetupTrafficControl();

	logfile = fopen(ltLogFile, "a+b");
	if(!logfile)
	{
		fprintf(stderr, "fopen(%s) failed: %s\n", ltLogFile, strerror(errno));
		exit(1);
	}
}
__attribute__((cold)) void TerminateActions()
{
	fclose(logfile);
}


void FlushLog()
{
	if(logfile_buffered_writes)
	{
		fflush(logfile);
		logfile_buffered_writes = 0;
	}
}

void TakeAction(const char *ip, const struct AnalyzePlanAction *action, long bandwidth_used, int used_interval)
{
	fprintf(stderr, "TakeAction(%s) called: action=%i\n", ip, action->type);
	
	if(is_legitimate_search_engine(ip))
	{
		fprintf(stderr, "TakeAction: ignoring %s, it's a search engine.\n", ip);
		return;
	}
	
	logfile_buffered_writes ++;
	fprintf(logfile, "[%li] %s USED %li IN %i (> %li, %.2f times) %s(%i)\n",
		TIME, ip, bandwidth_used, used_interval, action->level, (float) bandwidth_used / action->level,
		action_text[action->type], action->bandwidth_limit
	);

	if(action->type == LIMITTRAF_ACTION_LOG)
		return;
	
	if(action->type == LIMITTRAF_ACTION_LIMIT)
	{
		/* TODO: do something */
		
		
		
		return;
	}
	
	
	/* TODO: do something */
}
