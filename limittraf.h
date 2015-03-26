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

#ifndef _LIMITTRAF_H
#define _LIMITTRAF_H

#include <time.h>

extern const char *ltTc; /* Path to the 'tc' binary */
extern const char *ltNetworkInterface; /* e.g. 'eth0' */

extern const char *ltDbFile;
extern const char *ltLogFile;

extern time_t TIME; /* = time(NULL), an approximation for timestamp of current packet */

#endif
