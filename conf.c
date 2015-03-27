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

#include <pcre.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include "conf.h"

static const int CONF_LINE_MAX = 4096;

const char *action_text[] = { "LOG", "LIMIT", "BLOCK", "JAIL" };

struct AnalyzePlan PLAN;
int PLAN_limit_triggers_count = 0;

struct CfgTrigger
{
	/* 1) If 'limit_used' is downloaded in 'limit_interval' seconds, ... */
	int limit_interval; /* seconds */
	long limit_used; /* bytes */
	
	/* 2) ... then undertake 'action' */
	int action;
	
	/* if action=LIMITTRAF_ACTION_LIMIT, then reduce outgoing bandwidth to this client to bandwidth_limit */
	int bandwidth_limit; /* bytes (per second) */
};

/*
	Convert "G", "M", "K", "" into a numeric multiplier.
*/
static inline int size_prefix(const char *prefix)
{
	char c = toupper(*prefix);
	
	if(c == '\0') return 1;
	if(c == 'K') return 1<<10;
	if(c == 'M') return 1<<20;
	if(c == 'G') return 1<<30;
	
	fprintf(stderr, "Unknown size prefix: '%s'\n", prefix);
	exit(1);
}
/*
	Convert "h", "m", "" into a numeric multiplier.
*/
static inline int time_prefix(const char *prefix)
{
	char c = tolower(*prefix);

	if(c == 's' || c == '\0') return 1;
	if(c == 'm') return 60;
	if(c == 'h') return 3600;
	if(c == 'd') return 24 * 3600;

	fprintf(stderr, "Unknown time prefix: '%s'\n", prefix);
	exit(1);
}
/*
	Convert "LOG", "LIMIT", "BLOCK", "JAIL" into a numeric multiplier.
*/
static inline int action(const char *str)
{
	if(*str == 'L')
	{
		if(!strcmp(str, "LOG"))
			return LIMITTRAF_ACTION_LOG;
		if(!strcmp(str, "LIMIT"))
			return LIMITTRAF_ACTION_LIMIT;
	}
	if(!strcmp(str, "BLOCK"))
		return LIMITTRAF_ACTION_BLOCK;
	if(!strcmp(str, "JAIL"))
		return LIMITTRAF_ACTION_JAIL;
		
	fprintf(stderr, "Unknown action: '%s'\n", str);
	exit(1);
}

__attribute__((cold)) static int compare_analyze_actions_desc(const void *a, const void *b)
{
	return ((struct AnalyzePlanAction *) b)->level - ((struct AnalyzePlanAction *) a)->level;
}
__attribute__((cold)) static int compare_analyze_intervals_asc(const void *a, const void *b)
{
	return ((struct AnalyzePlanInterval *) a)->seconds - ((struct AnalyzePlanInterval *) b)->seconds;
}



/*
	ReadConfiguration() - populate the PLAN structure.
	
	Note: PLAN is always used in the limittraf main loop, so there's
	no point in freeing memory allocated for it here.
*/
__attribute__((cold))
void ReadConfiguration(const char *filename)
{
	FILE *conf_file;
	char *buffer; 
	char *p;
	int lineno, trigger_idx;
	pcre *cfg_regex;
	pcre_extra *cfg_extra;
	const char **listptr;
	int err, matched;
	int ovector[24]; /* (7 subexpressions + 1 whole expression) multiplied by 3, as needed for pcre_exec */
	const char CONFIG_REGEX[] = "^USED\\s+([0-9]+)([KMG]?)\\s+IN\\s+([0-9]+)([dhms]?)\\s*=\\s*(LIMIT|LOG|JAIL|BLOCK)\\s*(?:([0-9]+)([km]?)|)\\s*$";
	const int LIMITTRAF_TRIGGERS_MAX = 200;
	struct CfgTrigger *triggers;
	const char *error; int erroffset;
	
	cfg_regex = pcre_compile(CONFIG_REGEX, PCRE_NO_UTF8_CHECK, &error, &erroffset, NULL);
	if(!cfg_regex)
	{
		fprintf(stderr, "Failed to compile regexp: '%s': %s\n", CONFIG_REGEX, error);
		exit(1);
	}
	cfg_extra = pcre_study(cfg_regex, PCRE_STUDY_JIT_COMPILE, &error); /* returned NULL is ok here */
	
	conf_file = fopen(filename, "r");
	if(!conf_file)
	{
		fprintf(stderr, "fopen(%s) failed: %s\n", filename, strerror(errno));
		exit(1);
	}

	buffer = malloc(CONF_LINE_MAX);
	if(!buffer)
	{
		fprintf(stderr, "malloc(CONF_LINE_MAX = %i) failed: %s\n", CONF_LINE_MAX, strerror(errno));
		exit(1);
	}
	
	triggers = malloc(sizeof(struct CfgTrigger) * LIMITTRAF_TRIGGERS_MAX);
	if(!triggers)
	{
		fprintf(stderr, "malloc() for triggers failed: %s\n", strerror(errno));
		exit(1);
	}
	
	/*
		Our task is to fill in the PLAN structure (for further use by Analyze()).
		First we read all USED rules into 'triggers' and them restructure them inside the PLAN.
	*/
	
	lineno = 1;
	trigger_idx = 0;
	PLAN_limit_triggers_count = 0;
	while(fgets(buffer, CONF_LINE_MAX, conf_file))
	{
		int len = strlen(buffer) - 1;
		if(len <= 0) continue; /* empty string (0 if in the middle of file, -1 if last) */
		buffer[len] = '\0'; // remove \n
		
		p = strchr(buffer, '#'); // detect a comment
		if(p)
		{
			*p = '\0';
			len = p - buffer;
		}
		
		if(buffer[0] == '\0') /* comment only */
			continue;
			
		matched = pcre_exec(cfg_regex, cfg_extra, buffer, len, 0, 0, ovector, 24);
		if(matched < 0)
		{
			if(matched == PCRE_ERROR_NOMATCH)
				fprintf(stderr, "%s:%i: unknown configuration directive: %s\n", filename, lineno, buffer);
			else
				fprintf(stderr, "pcre_exec() returned %i on [[%s]]\n", matched, buffer);
			continue;
		}
		if(matched < 5)
		{
			fprintf(stderr, "%s:%i: syntax error: %s\n", filename, lineno, buffer);
			exit(1);
		}
		
		listptr = NULL;
		err = pcre_get_substring_list(buffer, ovector, matched, &listptr);
		if(err < 0)
		{
			fprintf(stderr, "pcre_get_substring_list(): error %i\n", err);
			exit(1);
		}
		
		if(trigger_idx >= LIMITTRAF_TRIGGERS_MAX)
		{
			fprintf(stderr, "Too many triggers: please use no more than LIMITTRAF_TRIGGERS_MAX (%i)\n", LIMITTRAF_TRIGGERS_MAX);
			exit(1);
		}
		
		triggers[trigger_idx].limit_interval = atoi(listptr[3]) * time_prefix(listptr[4]);
		triggers[trigger_idx].limit_used = atoi(listptr[1]) * size_prefix(listptr[2]);
		triggers[trigger_idx].action = action(listptr[5]);
		
		if(triggers[trigger_idx].action == LIMITTRAF_ACTION_LIMIT)
		{
			PLAN_limit_triggers_count ++;
			triggers[trigger_idx].bandwidth_limit = atoi(listptr[6]) * size_prefix(listptr[7]);
		}
		else triggers[trigger_idx].bandwidth_limit = 0;
		
		trigger_idx ++;

#if 0
		fprintf(stderr, "DEBUG: pcre_exec() returned %i on [[%s]]\n", matched, buffer);
		int i = 0;
		for(i = 0; i < matched; i ++)
			fprintf(stderr, "DEBUG-substring[%i]: %s\n", i, listptr[i]);
		fprintf(stderr, "---");
#endif
		
		pcre_free_substring_list(listptr);
		lineno ++;
	}
	
	/* Now we convert 'triggers' into PLAN.
		1. how many intervals do we have?
	*/
	PLAN.count = 0; // trigger_idx minus <something>
	PLAN.intervals = /* preallocate some space (will be scaled down with realloc later) */
		malloc(LIMITTRAF_TRIGGERS_MAX * sizeof(struct AnalyzePlanInterval));
	if(!PLAN.intervals)
	{
 		fprintf(stderr, "malloc() for PLAN failed: %s\n", strerror(errno));
		exit(1);
	}
	
	int i, j;
	for(i = 0; i < trigger_idx; i ++)
	{
#if 0
		fprintf(stderr, "DEBUG: trigger: limit_interval = %i, limit_used = %li, action = %i, bandwidth_limit = %i\n",
			triggers[i].limit_interval,
			triggers[i].limit_used,
			triggers[i].action,
			triggers[i].bandwidth_limit
		);
#endif
	
		int already_counted = -1;
		for(j = 0; j < PLAN.count; j ++)
		{
			if(triggers[i].limit_interval == PLAN.intervals[j].seconds)
			{
				already_counted = j;
				break;
			}
		}
		
		if(already_counted == -1)
		{
			PLAN.intervals[PLAN.count].seconds = triggers[i].limit_interval;
			PLAN.intervals[PLAN.count].count = 1;
			PLAN.count ++;
		}
		else
		{
			PLAN.intervals[j].count ++;
		}
	}	
	
	fprintf(stderr, "DEBUG: %i different intervals\n", PLAN.count);
	PLAN.intervals = realloc(PLAN.intervals, PLAN.count * sizeof(struct AnalyzePlanInterval));
	if(!PLAN.intervals)
	{
 		fprintf(stderr, "realloc() for PLAN failed: %s\n", strerror(errno));
		exit(1);
	}
	
	/*
		2. Place actions into PLAN.intervals[...].actions[] arrays.
		3. Sort them by 'level' (from lower to higher values).
	*/
	for(j = 0; j < PLAN.count; j ++)
	{
		int action_idx = 0;

		PLAN.intervals[j].actions = malloc(PLAN.intervals[j].count * sizeof(struct AnalyzePlanAction));
		if(!PLAN.intervals[j].actions)
		{
			fprintf(stderr, "malloc() for PLAN actions failed: %s\n", strerror(errno));
			exit(1);
		}
		
		for(i = 0; i < trigger_idx; i ++)
		{
			if(PLAN.intervals[j].seconds == triggers[i].limit_interval)
			{
				PLAN.intervals[j].actions[action_idx].level = triggers[i].limit_used;
				PLAN.intervals[j].actions[action_idx].type = triggers[i].action;
				PLAN.intervals[j].actions[action_idx].bandwidth_limit = triggers[i].bandwidth_limit;
				action_idx ++;
			}
		}
		
		qsort(PLAN.intervals[j].actions, action_idx, sizeof(struct AnalyzePlanAction), compare_analyze_actions_desc);
	}

	/*
		4. Sort the intervals, from smaller to bigger.
		(for further I/O optimization: e.g. when Analyze checks the rule for 15M first
		and for 360M after that, data on those 15M is probably still in the disc cache;
		on the other hand, if we read 360M first, OS could unload it from memory prematurely.)
	*/
	qsort(PLAN.intervals, PLAN.count, sizeof(struct AnalyzePlanInterval), compare_analyze_intervals_asc);

#if 1
	for(j = 0; j < PLAN.count; j ++)
	{
		fprintf(stderr, "DEBUG: interval = %i seconds, %i actions\n",
			PLAN.intervals[j].seconds, PLAN.intervals[j].count);
		for(i = 0; i < PLAN.intervals[j].count; i ++)
			fprintf(stderr, "DEBUG:     level = %li bytes, action = %i, bandwidth_limit = %i\n",
				PLAN.intervals[j].actions[i].level,
				PLAN.intervals[j].actions[i].type,
				PLAN.intervals[j].actions[i].bandwidth_limit
			);
	}
#endif
	
	free(triggers);
	free(buffer);
	fclose(conf_file);
	if(cfg_extra) pcre_free_study(cfg_extra);
		
//	fprintf(stderr, "DEBUG: deliberate exit() from ReadConfiguration()\n");
//	exit(0); // NOTE DEBUG
}
