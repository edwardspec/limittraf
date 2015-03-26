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

#ifndef _LIMITTRAF_DATABASE_H
#define _LIMITTRAF_DATABASE_H

#include <inttypes.h>

/*
	Create the database.
	Must be called before any other database-related method.
*/
void InitializeDb();

/*
	Free all resources associated with the database.
*/
void TerminateDb();

/*
	DbMemoryUsed() = sqlite3_memory_used(). 
*/
uint64_t DbMemoryUsed();

/*
	Called from Analyze() and when in-memory DB 'dbh' exceeds ltMemoryDumpLevel.
	It does two things:
	1. merges several rows of in-memory 'packet' into one on-disc 'packet';
	2. cleans in-memory 'packet'.
	
	You should call CommitTransaction() before CompactDb()
		and BeginTransaction() afterwards.
*/
void CompactDb();


/* 
	LegSearch_Save() - write legsearch table from in-memory DB to disc
		(called periodically so that the legsearch cache is not purged
		if the application is stopped or restarted)
*/
void LegSearch_Save();

/*
	Fetch a value from legsearch cache.
	Returns:
		-1 - cache miss,
		0 or 1 - cache hit (0 - not a search engine, 1 - verified search engine).
*/
int LegSearch_Get(const char *ip);

/*
	Write a value into legsearch cache.
*/
void LegSearch_Set(const char *ip, int value);

/*
	CommitTransaction() and BeginTransaction()
		- invoke low-level COMMIT and BEGIN operations.
	NOTE: a transaction is always started by InitializeDb(), so if you need
	to do something outside of the Register operations (e.g. call
	CompactDb), you should call CommitTransaction() first, then do whatever
	you need, then create a new transaction with BeginTransaction().
	WARNING: DO NOT FORGET to call BeginTransaction() afterwards.
*/
void CommitTransaction();
void BeginTransaction();

/*
	Register a packet in the in-memory 'packet' database.
*/
void Register(const char *ip, unsigned int length);

/*
	Scan the database for clients who violate some rules from the PLAN,
	determine the appropriate action and call TakeAction().
*/
void AnalyzeDb();

#endif
