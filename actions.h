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

#ifndef _LIMITTRAF_ACTIONS_H
#define _LIMITTRAF_ACTIONS_H

#include "conf.h"

/* should be called from Initialize()/Terminate().
	NOTE: InitializeActions() MUST be called after ReadConfiguration().
*/
void InitializeActions();
void TerminateActions();

/*
	Apply action to the specified IP.
	
	NOTE: bandwidth_used and used_interval are only needed for logging,
	they are irrelevant to the restricting action inself.
*/
void TakeAction(const char *ip, const struct AnalyzePlanAction *action,
	long bandwidth_used, int used_interval);

/* FlushLog() - should be called after a group of TakeAction() calls */
void FlushLog();

#endif

