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

/* <Configuration> */

#ifndef _LIMITTRAF_CONF_H
#define _LIMITTRAF_CONF_H

#define LIMITTRAF_ACTION_LOG 0
#define LIMITTRAF_ACTION_LIMIT 1
#define LIMITTRAF_ACTION_BLOCK 2
#define LIMITTRAF_ACTION_JAIL 3

extern const char *action_text[]; /* action_text[0] = "LOG", etc.; defined in conf.c */

struct AnalyzePlan /* parsed configuration, as optimized for Analyze() call */
{
	int count; /* number of different intervals */
	struct AnalyzePlanInterval *intervals;
};
struct AnalyzePlanInterval
{
	int seconds; /* = limit_interval from CfgTrigger */
	
	int count;
	struct AnalyzePlanAction *actions;
};
struct AnalyzePlanAction
{
	long level; /* = limit_used from CfgTrigger */

	int type; /* = action from CfgTrigger */
	int bandwidth_limit; /* = bandwidth_limit from CfgTrigger */
};

extern struct AnalyzePlan PLAN; /* created by ReadConfiguration() and used by Analyze() */
extern int PLAN_limit_triggers_count; /* calculated by ReadConfiguration() and used by SetupTrafficControl() */

/* </Configuration> */

void ReadConfiguration();

#endif
