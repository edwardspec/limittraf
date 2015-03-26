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

#ifndef _LIMITTRAF_LEGSEARCH_H
#define _LIMITTRAF_LEGSEARCH_H

/* Compile the regex used by is_legitimate_search_engine() */
void InitializeLegSearch();

/* Free the regex compiled by InitializeLegSearch() */
void TerminateLegSearch();


/**

	@retval 1 A legitimate search engine.
	@retval 0 Not a search engine (or unknown search engine).
	@todo result caching
*/
int is_legitimate_search_engine(const char *ip);

#endif
