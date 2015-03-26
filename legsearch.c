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

#include <netdb.h>
#include <arpa/inet.h>
#include <limits.h>
#include <string.h>
#include <pcre.h>
#include <stdio.h>

#include "database.h"
#include "legsearch.h"

const char LEGSEARCH_REGEX[] = "(?:googlebot\\.com|yandex\\.(?:ru|net|com)|mail\\.ru)$"; /* applied to DNS names of client IPs */
int is_legitimate_search_engine(const char *ip);
int legsearch_cache_hit_counter = 0;
int legsearch_cache_miss_counter = 0;

pcre *legsearch_regex;
pcre_extra *legsearch_extra;

__attribute__((cold)) void InitializeLegSearch()
{
	const char *error; int erroffset;

	legsearch_regex = pcre_compile(LEGSEARCH_REGEX, PCRE_NO_UTF8_CHECK, &error, &erroffset, NULL);
	if(!legsearch_regex)
	{
		fprintf(stderr, "Failed to compile regexp: '%s': %s\n", LEGSEARCH_REGEX, error);
		exit(1);
	}
	legsearch_extra = pcre_study(legsearch_regex, PCRE_STUDY_JIT_COMPILE, &error); /* returned NULL is ok here */
}

__attribute__((cold)) void TerminateLegSearch()
{
	if(legsearch_extra)
		pcre_free_study(legsearch_extra);
	legsearch_extra = NULL;
}

static int _is_legitimate_search_engine_uncached(const char *ip)
{
	struct hostent *host;
	struct in_addr addr;
	char hostname[HOST_NAME_MAX + 1];
	int hostname_len;
	char **p;
	int ret;

	if(!legsearch_regex)
	{
		fprintf(stderr, "BUG: legsearch_regex is NULL: forgot to call InitializeLegSearch()?\n");
		InitializeLegSearch();
	}
	
	if(inet_pton(AF_INET, ip, &addr) != 1) /* should not happen: IP format is assured by REGEX string */
		return 0;

	host = gethostbyaddr(&addr, sizeof(addr), AF_INET);
	if(!host) return 0; /* lookup failed */

	hostname_len = strlen(host->h_name);
	ret = pcre_exec(legsearch_regex, legsearch_extra, host->h_name, hostname_len, 0, 0, NULL, 0);
	if(ret < 0) return 0; /* reverse DNS entry for IP does not point to DNS names of common search engines */
	
	/* we must copy the hostname */
	strncpy(hostname, host->h_name, hostname_len);
	hostname[hostname_len] = '\0';
	
	/* Check if this reverse DNS entry wasn't lying by making A query */
	host = gethostbyname(hostname);
	if(!host) return 0; /* lookup failed */
	
	for(p = host->h_addr_list; *p != NULL; p ++)
	{
		if(!memcmp(*p, &addr, sizeof(addr)))
			return 1;
	}
	
	return 0;
}

int is_legitimate_search_engine(const char *ip)
{
	/*
		Let's search the cache first
	*/
	int is_search_engine = LegSearch_Get(ip);
	
	/* Do we have the result? */
	if(is_search_engine != -1)
	{
		legsearch_cache_hit_counter ++;
		return is_search_engine;
	}
	legsearch_cache_miss_counter ++;
	
	is_search_engine = _is_legitimate_search_engine_uncached(ip); 
	
	/*
		Save the result in cache
	*/
	LegSearch_Set(ip, is_search_engine);

	return is_search_engine;
}
