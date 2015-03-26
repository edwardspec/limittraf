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

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>

#include "limittraf.h"
#include "database.h"
#include "conf.h"
#include "actions.h"

sqlite3 *dbh; /* in-memory database */
sqlite3_stmt *sth_register;
sqlite3_stmt *sth_analyze_range;
sqlite3_stmt *sth_legsearch_get, *sth_legsearch_set, *sth_legsearch_deprecate_all;
sqlite3_stmt *sth_insert_compact_db, *sth_clean_inmemory_packet_db;
sqlite3_stmt *sth_legsearch_clean, *sth_legsearch_save;
char *sql_error; int ret;

__attribute__((hot)) void CommitTransaction()
{
	sqlite3_exec(dbh, "COMMIT TRANSACTION", NULL, NULL, NULL);
}
__attribute__((hot)) void BeginTransaction()
{
	sqlite3_exec(dbh, "BEGIN TRANSACTION", NULL, NULL, NULL);
}

__attribute__((hot)) uint64_t DbMemoryUsed()
{
	return sqlite3_memory_used();
}

__attribute__((hot)) void CompactDb()
{
	ret = sqlite3_step(sth_insert_compact_db);
	sqlite3_reset(sth_insert_compact_db);
	if(ret != SQLITE_DONE)
		fprintf(stderr, "sqlite3_step(sth_insert_compact_db) failed at %s:%i: error %i: %s\n", __FILE__, __LINE__, ret, sqlite3_errmsg(dbh));
	
	ret = sqlite3_step(sth_clean_inmemory_packet_db);
	sqlite3_reset(sth_clean_inmemory_packet_db);
	if(ret != SQLITE_DONE)
		fprintf(stderr, "sqlite3_step(sth_clean_inmemory_packet_db) failed at %s:%i: error %i: %s\n", __FILE__, __LINE__, ret, sqlite3_errmsg(dbh));
}

__attribute__((hot)) void LegSearch_Save()
{
	/*
		NOTE: sth_legsearch_clean and sth_legsearch_save must form a transaction
		(so that if application is killed by a signal or power failure, the data
		removed by sth_legsearch_clean is recovered).
	*/
	sqlite3_exec(dbh, "BEGIN TRANSACTION", NULL, NULL, NULL);
	
	ret = sqlite3_step(sth_legsearch_clean);
	sqlite3_reset(sth_legsearch_clean);
	if(ret != SQLITE_DONE)
		fprintf(stderr, "sqlite3_step(sth_legsearch_clean) failed at %s:%i: error %i: %s\n", __FILE__, __LINE__, ret, sqlite3_errmsg(dbh));

	ret = sqlite3_step(sth_legsearch_save);
	sqlite3_reset(sth_legsearch_save);
	if(ret != SQLITE_DONE)
		fprintf(stderr, "sqlite3_step(sth_legsearch_save) failed at %s:%i: error %i: %s\n", __FILE__, __LINE__, ret, sqlite3_errmsg(dbh));
		
	sqlite3_exec(dbh, "END TRANSACTION", NULL, NULL, NULL);
}

int LegSearch_Get(const char *ip)
{
	int value;
	
	sqlite3_bind_text(sth_legsearch_get, 1, ip, -1, SQLITE_STATIC);
	ret = sqlite3_step(sth_legsearch_get);
	value = sqlite3_column_int(sth_legsearch_get, 0);
	sqlite3_reset(sth_legsearch_get);
	
	if(ret == SQLITE_ROW)
		return value;

	if(ret != SQLITE_DONE)
		fprintf(stderr, "sqlite3_step(sth_legsearch_get) failed at %s:%i: error %i: %s\n", __FILE__, __LINE__, ret, sqlite3_errmsg(dbh));
	return -1;
}

void LegSearch_Set(const char *ip, int value)
{
	sqlite3_bind_text(sth_legsearch_set, 1, ip, -1, SQLITE_STATIC);
	sqlite3_bind_int(sth_legsearch_set, 2, value);
	sqlite3_bind_int(sth_legsearch_set, 3, TIME);
	ret = sqlite3_step(sth_legsearch_set);
	sqlite3_reset(sth_legsearch_set);
	
	if(ret != SQLITE_DONE)
		fprintf(stderr, "sqlite3_step(sth_legsearch_set) failed at %s:%i: error %i: %s\n", __FILE__, __LINE__, ret, sqlite3_errmsg(dbh));
}

__attribute__((hot)) void Register(const char *ip, unsigned int length)
{
	sqlite3_bind_int(sth_register, 1, TIME);
	sqlite3_bind_text(sth_register, 2, ip, -1, SQLITE_STATIC);
	sqlite3_bind_int(sth_register, 3, length);
	ret = sqlite3_step(sth_register);
	sqlite3_reset(sth_register);
	if(ret != SQLITE_DONE)
		fprintf(stderr, "sqlite3_step(sth_register) failed at %s:%i: error %i: %s\n", __FILE__, __LINE__, ret, sqlite3_errmsg(dbh));
}

__attribute__((cold)) void InitializeDb()
{
	sqlite3_stmt *sth_attach;

	ret = sqlite3_open(":memory:", &dbh);
	if(ret != SQLITE_OK)
	{
		fprintf(stderr, "Failed to open in-memory SQLite DB: error %i: %s\n", ret, sqlite3_errmsg(dbh));
		exit(1);
	}
	
	/* Now we attach the database file.
		NOTE: CompactDb() will optimize the in-memory database and transfer in onto the disc.
		This is required to reduce the number of I/O operations.
	*/
	ret = sqlite3_prepare_v2(dbh, "ATTACH ? AS ondisc", -1,
		&sth_attach, NULL);
	if(ret != SQLITE_OK)
	{
		fprintf(stderr, "Failed to compile ATTACH DATABASE query 'sth_attach': error %i: %s\n", ret, sqlite3_errmsg(dbh));
		exit(1);
	}
	sqlite3_bind_text(sth_attach, 1, ltDbFile, -1, SQLITE_STATIC);
	ret = sqlite3_step(sth_attach);
	if(ret != SQLITE_DONE)
		fprintf(stderr, "sqlite3_step(sth_attach) failed at %s:%i: error %i: %s\n", __FILE__, __LINE__, ret, sqlite3_errmsg(dbh));
	sqlite3_finalize(sth_attach);

	/*
		packet table: here we list the lengths of all intercepted packets.
		Exists both in in-memory and on-disc databases.
	*/
	ret = sqlite3_exec(dbh,
		"CREATE TABLE IF NOT EXISTS packet (p_time INTEGER, p_ip TEXT, p_len INTEGER)",
		NULL, NULL, &sql_error);
	if(ret != SQLITE_OK)
	{	
		fprintf(stderr, "Failed to create in-memory SQLite table 'packet': %s\n", sql_error);
		sqlite3_free(sql_error);
		exit(1);
	}
	ret = sqlite3_exec(dbh,
		"CREATE TABLE IF NOT EXISTS ondisc.packet (p_time INTEGER, p_ip TEXT, p_len INTEGER)",
		NULL, NULL, &sql_error);
	if(ret != SQLITE_OK)
	{	
		fprintf(stderr, "Failed to create SQLite table 'packet': %s\n", sql_error);
		sqlite3_free(sql_error);
		exit(1);
	}
	
	ret = sqlite3_exec(dbh,
		"CREATE INDEX IF NOT EXISTS ondisc.packet_time ON packet (p_time)",
		NULL, NULL, &sql_error);
	if(ret != SQLITE_OK)
	{	
		fprintf(stderr, "Failed to create SQLite index 'ondisc.packet_time' on 'packet(p_time)': %s\n", sql_error);
		sqlite3_free(sql_error);
		exit(1);
	}
	
	/*
		'legsearch' is a cache used by is_legitimate_search_engine() to
		avoid unneeded DNS lookups.
		Exists both in in-memory and on-disc databases.
		If on-disc version exists, it is loaded into memory.
		Later LegSearch_Save() dumps in-memory database back to file.
	*/
	ret = sqlite3_exec(dbh,
		"CREATE TABLE IF NOT EXISTS ondisc.legsearch (ls_ip TEXT PRIMARY KEY, ls_is_search_engine BOOLEAN, ls_updated INTEGER)",
		NULL, NULL, &sql_error);
	if(ret != SQLITE_OK)
	{	
		fprintf(stderr, "Failed to create SQLite table 'legsearch': %s\n", sql_error);
		sqlite3_free(sql_error);
		exit(1);
	}
	ret = sqlite3_exec(dbh,
		"CREATE TABLE IF NOT EXISTS legsearch AS SELECT ls_ip, ls_is_search_engine, ls_updated FROM ondisc.legsearch",
		NULL, NULL, &sql_error);
	if(ret != SQLITE_OK)
	{	
		fprintf(stderr, "Failed to create in-memory SQLite table 'legsearch': %s\n", sql_error);
		sqlite3_free(sql_error);
		exit(1);
	}
	
	ret = sqlite3_exec(dbh,
		"CREATE INDEX IF NOT EXISTS legsearch_ip ON legsearch (ls_ip)",
		NULL, NULL, &sql_error);
	if(ret != SQLITE_OK)
	{	
		fprintf(stderr, "Failed to create in-memory SQLite index 'legsearch_ip' on 'legsearch(ls_ip)': %s\n", sql_error);
		sqlite3_free(sql_error);
		exit(1);
	}
	
	ret = sqlite3_prepare_v2(dbh, "SELECT ls_is_search_engine FROM legsearch WHERE ls_ip = ?", -1,
		&sth_legsearch_get, NULL);
	if(ret != SQLITE_OK)
	{
		fprintf(stderr, "Failed to compile INSERT query 'legsearch_get' for 'legsearch': error %i: %s\n", ret, sqlite3_errmsg(dbh));
		exit(1);
	}
	
	ret = sqlite3_prepare_v2(dbh, "REPLACE INTO legsearch(ls_ip, ls_is_search_engine, ls_updated) VALUES (?, ?, ?)", -1,
		&sth_legsearch_set, NULL);
	if(ret != SQLITE_OK)
	{
		fprintf(stderr, "Failed to compile INSERT query 'legsearch_set' for 'legsearch': error %i: %s\n", ret, sqlite3_errmsg(dbh));
		exit(1);
	}
	
	ret = sqlite3_prepare_v2(dbh, "DELETE FROM legsearch WHERE ls_updated < ?", -1,
		&sth_legsearch_deprecate_all, NULL);
	if(ret != SQLITE_OK)
	{
		fprintf(stderr, "Failed to compile INSERT query 'legsearch_deprecate_all' for 'legsearch': error %i: %s\n", ret, sqlite3_errmsg(dbh));
		exit(1);
	}
	
	/*
		sth_insert_compact_db, sth_clean_inmemory_packet_db
			are statements used in CompactDb()
	*/
	ret = sqlite3_prepare_v2(dbh, "INSERT INTO ondisc.packet (p_time, p_ip, p_len) SELECT CAST(ROUND(p_time * 0.1) * 10 AS INTEGER), p_ip, SUM(p_len) FROM packet GROUP BY ROUND(p_time * 0.1) * 10, p_ip", -1,
		&sth_insert_compact_db, NULL);
	if(ret != SQLITE_OK)
	{
		fprintf(stderr, "Failed to compile INSERT TABLE query 'sth_insert_compact_db': error %i: %s\n", ret, sqlite3_errmsg(dbh));
		fprintf(stderr, "SQLITE error message: %s\n", sqlite3_errmsg(dbh));
		exit(1);
	}
	ret = sqlite3_prepare_v2(dbh, "DELETE FROM packet", -1,
		&sth_clean_inmemory_packet_db, NULL);
	if(ret != SQLITE_OK)
	{
		fprintf(stderr, "Failed to compile DELETE query 'sth_clean_inmemory_packet_db' for 'packet': error %i: %s\n", ret, sqlite3_errmsg(dbh));
		fprintf(stderr, "SQLITE error message: %s\n", sqlite3_errmsg(dbh));
		exit(1);
	}
	
	/*
		sth_legsearch_clean, sth_legsearch_save are the statement used in LegSearch_Save()
	*/
	ret = sqlite3_prepare_v2(dbh, "INSERT INTO ondisc.legsearch (ls_ip, ls_is_search_engine, ls_updated) SELECT ls_ip, ls_is_search_engine, ls_updated FROM legsearch", -1,
		&sth_legsearch_save, NULL);
	if(ret != SQLITE_OK)
	{
		fprintf(stderr, "Failed to compile INSERT query 'sth_legsearch_save' for 'ondisc.legsearch': error %i: %s\n", ret, sqlite3_errmsg(dbh));
		fprintf(stderr, "SQLITE error message: %s\n", sqlite3_errmsg(dbh));
		exit(1);
	}
	ret = sqlite3_prepare_v2(dbh, "DELETE FROM ondisc.legsearch", -1,
		&sth_legsearch_clean, NULL);
	if(ret != SQLITE_OK)
	{
		fprintf(stderr, "Failed to compile DELETE query 'sth_legsearch_clean' for 'ondisc.legsearch': error %i: %s\n", ret, sqlite3_errmsg(dbh));
		fprintf(stderr, "SQLITE error message: %s\n", sqlite3_errmsg(dbh));
		exit(1);
	}
	
	/*
		sth_register is called for every intercepted packet
	*/
	ret = sqlite3_prepare_v2(dbh, "INSERT INTO packet(p_time, p_ip, p_len) VALUES(?, ?, ?)", -1,
		&sth_register, NULL);
	if(ret != SQLITE_OK)
	{
		fprintf(stderr, "Failed to compile INSERT query 'sth_register' for 'packet': error %i: %s\n", ret, sqlite3_errmsg(dbh));
		exit(1);
	}
	
	ret = sqlite3_prepare_v2(dbh, "SELECT p_ip, SUM(p_len) FROM ondisc.packet WHERE p_time > ? AND p_time < ? GROUP BY p_ip HAVING SUM(p_len) > ?  ORDER BY SUM(p_len) DESC", -1,
		&sth_analyze_range, NULL);
	if(ret != SQLITE_OK)
	{
		fprintf(stderr, "Failed to compile SELECT query 'sth_analyze_range' for 'packet': error %i: %s\n", ret, sqlite3_errmsg(dbh));
		exit(1);
	}

	/* Start scanning log and writing to DB */
	ret = sqlite3_exec(dbh, "BEGIN TRANSACTION", NULL, NULL, &sql_error);
	if(ret != SQLITE_OK)
	{	
		fprintf(stderr, "Failed to begin transaction: %s\n", sql_error);
		sqlite3_free(sql_error);
		exit(1);
	}
}

void TerminateDb()
{
	ret = sqlite3_exec(dbh, "COMMIT TRANSACTION", NULL, NULL, &sql_error);
	if(ret != SQLITE_OK)
	{	
		fprintf(stderr, "Failed to end transaction: %s\n", sql_error);
		sqlite3_free(sql_error);
	}
	
	sqlite3_finalize(sth_analyze_range);
	sqlite3_finalize(sth_register);
	sqlite3_finalize(sth_insert_compact_db);
	
	sqlite3_finalize(sth_legsearch_deprecate_all);
	sqlite3_finalize(sth_legsearch_set);
	sqlite3_finalize(sth_legsearch_get);
	
	ret = sqlite3_exec(dbh, "DETACH ondisc", NULL, NULL, &sql_error);
	if(ret != SQLITE_OK)
	{	
		fprintf(stderr, "Failed to detach SQLite database 'ondisc': %s\n", sql_error);
		sqlite3_free(sql_error);
		exit(1);
	}
	
	sqlite3_close(dbh);
}

__attribute__((hot)) void AnalyzeDb()
{
	const unsigned char *ip;
	long used; /* = SUM(p_len) for this IP */
	struct AnalyzePlanAction *action;
	
	int i, j;
	for(i = 0; i < PLAN.count; i ++)
	{
		/*
			Analyze query (sth_analyze_range) is executed
			once per interval.
			
			NOTE: PLAN.intervals[i].actions is sorted by level (ASC),
			therefore actions[0].level is the lowest one.
		*/
		sqlite3_bind_int(sth_analyze_range, 1, TIME - PLAN.intervals[i].seconds);
		sqlite3_bind_int(sth_analyze_range, 2, TIME);
		sqlite3_bind_int(sth_analyze_range, 3, PLAN.intervals[i].actions[0].level);
	
		while(1)
		{
			ret = sqlite3_step(sth_analyze_range);
			if(ret != SQLITE_ROW) break;
			
			/* TODO */
			ip = sqlite3_column_text(sth_analyze_range, 0);
			used = sqlite3_column_int(sth_analyze_range, 1);
			
			/* Determine which action to apply. Keep in mind that actions[] are sorted by level (ASC) */
			for(j = PLAN.intervals[i].count - 1; j >= 0; j --)
			{
				if(used >= PLAN.intervals[i].actions[j].level)
				{
					action = &PLAN.intervals[i].actions[j];
					break;
				}
			}
			
			fprintf(stderr, "AnalyzeDb(): %s downloaded %.2f kilobytes in %i seconds (%.2f times the normal level %li): action would be %i\n",
				ip, used / 1024., PLAN.intervals[i].seconds, (float) used / PLAN.intervals[i].actions[0].level, PLAN.intervals[i].actions[0].level,
				action->type
			);

			TakeAction((const char *) ip, action, used, PLAN.intervals[i].seconds);
		}
		
		/* */
		if(ret != SQLITE_DONE)
			fprintf(stderr, "sqlite3_step(sth_analyze_range) failed at %s:%i: error %i: %s\n", __FILE__, __LINE__, ret, sqlite3_errmsg(dbh));
		
		sqlite3_reset(sth_analyze_range);
	}
	FlushLog();
}
