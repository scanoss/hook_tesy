// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/query.c
 *
 * High level data queries
 *
 * Copyright (C) 2018-2021 SCANOSS.COM
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#include "query.h"
#include "util.h"
#include "time.h"
#include "limits.h"
#include "ldb.h"
#include "scanoss.h"
#include "decrypt.h"

/* Obtain the first file name for the given file MD5 hash */
char *get_filename(char *md5)
{
	/* Convert md5 to bin */
	uint8_t md5bin[MD5_LEN];
	ldb_hex_to_bin(md5, MD5_LEN * 2, md5bin);

	/* Init record */
	uint8_t *record = calloc(LDB_MAX_REC_LN + 1, 1);

	/* Fetch first record */
	ldb_get_first_record(oss_file, md5bin, (void *) record);

	uint32_t recln = uint32_read(record);
	if (record)
	{
		memmove(record, record + 4, recln);
		record[recln] = 0;

		/* Decrypt data */
		decrypt_data(record, recln, "file", md5bin, md5bin + LDB_KEY_LN);
	}

	return (char *)record;
}

/* Handler function for get_url_record */
bool ldb_get_first_url_not_ignored(uint8_t *key, uint8_t *subkey, int subkey_ln, uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	decrypt_data(data, datalen, "url", key, subkey);

	uint8_t *record = (uint8_t *) ptr;

	if (datalen) if (!ignored_asset_match(data + 4))
	{
		/* Not ignored, means copy record and exit */
		uint32_write(record, datalen);
		memcpy(record + 4, data, datalen);
		record[datalen + 4 + 1] = 0;
		return true;
	}

	return false;
}

/* Obtain the first available component record for the given MD5 hash */
void get_url_record(uint8_t *md5, uint8_t *record)
{
	/* Erase byte count */
	uint32_write(record, 0);

	/* Fetch record */
	ldb_fetch_recordset(NULL, oss_url, md5, false, ldb_get_first_url_not_ignored, (void *) record);

	/* Erase record length prefix from record */
	uint32_t recln = uint32_read(record);
	if (recln) 
	{
		memmove(record, record+4, recln);
		record[recln] = 0;
	}

}

/* Extracts component age in seconds from created date (1st CSV field in data) */
bool handle_get_component_age(uint8_t *key, uint8_t *subkey, int subkey_ln, \
uint8_t *data, uint32_t datalen, int iteration, void *ptr)
{
	long *age = (long *) ptr;

	decrypt_data(data, datalen, "purl", key, subkey);

	/* Expect at least a date*/
	if (datalen < 9) return false;

	/* Ignore purl relation records */
	if (!memcmp(data, "pkg:", 4)) return false;

	/* Extract created date (1st CSV field) from popularity record */
	char date[MAX_FIELD_LN] = "\0";
	extract_csv(date, (char *) data, 1, MAX_FIELD_LN);

	/* Expect date separators. Format 2009-03-21T22:32:25Z */
	if (date[4] != '-' || date[7] != '-') return false;

	/* Chop date string into year, month and day strings */
	date[4] = 0;
	date[7] = 0;
	date[10] = 0;

	/* Extract year */
	int year = atoi(date) - 1900;
	if (year < 0) return false;

	/* Extract year */
	int month = atoi(date + 5) - 1;
	if (month < 0) return false;

	/* Extract year */
	int day = atoi(date + 8);
	if (day < 0) return false;

	/* Fill time structure */
	struct tm t;
	time_t epoch;
	t.tm_year = year;
	t.tm_mon = month;
	t.tm_mday = day;
	t.tm_hour = 0;
	t.tm_min = 0;
	t.tm_sec = 0;
	t.tm_isdst = 0;
	epoch = mktime(&t);

	/* Keep the oldest date in case there are multiple sources */
	long seconds = (long) time (NULL) - (long) epoch;
	if (seconds > *age) *age = seconds;

	return false;
}

/* Return the age of a component in seconds */
int get_component_age(uint8_t *md5)
{
	if (!md5) return 0;

	/* Fetch record */
	long age = 0;

	if (ldb_table_exists(oss_purl.db, oss_purl.table)) //skip purl if the table is not present
		ldb_fetch_recordset(NULL, oss_purl, md5, false, handle_get_component_age, &age);

	return age;
}





#include "attributions.h"
#include "debug.h"
#include "file.h"
#include "help.h"
#include "ignorelist.h"
#include "license.h"
#include "limits.h"
#include "mz.h"
#include "parse.h"
#include "report.h"
#include "scan.h"
#include "scanoss.h"
#include "util.h"

struct ldb_table oss_url;
struct ldb_table oss_file;
struct ldb_table oss_wfp;
struct ldb_table oss_purl;
struct ldb_table oss_copyright;
struct ldb_table oss_quality;
struct ldb_table oss_vulnerability;
struct ldb_table oss_dependency;
struct ldb_table oss_license;
struct ldb_table oss_attribution;
struct ldb_table oss_cryptography;
component_item *ignore_components;
component_item *declared_components;

/* File tracing -qi */
uint8_t trace_id[MD5_LEN];
bool trace_on;

/* Initialize tables for the DB name indicated (defaults to oss) */
void initialize_ldb_tables(char *name)
{
	char oss_db_name[MAX_ARGLN];

	if (name) strcpy(oss_db_name, name);
	else strcpy(oss_db_name, DEFAULT_OSS_DB_NAME);

	strcpy(oss_url.db, oss_db_name);
	strcpy(oss_url.table, "url");
	oss_url.key_ln = 16;
	oss_url.rec_ln = 0;
	oss_url.ts_ln = 2;
	oss_url.tmp = false;

	strcpy(oss_file.db, oss_db_name);
	strcpy(oss_file.table, "file");
	oss_file.key_ln = 16;
	oss_file.rec_ln = 0;
	oss_file.ts_ln = 2;
	oss_file.tmp = false;

	strcpy(oss_wfp.db, oss_db_name);
	strcpy(oss_wfp.table, "wfp");
	oss_wfp.key_ln = 4;
	oss_wfp.rec_ln = 18;
	oss_wfp.ts_ln = 2;
	oss_wfp.tmp = false;

	strcpy(oss_purl.db, oss_db_name);
	strcpy(oss_purl.table, "purl");
	oss_purl.key_ln = 16;
	oss_purl.rec_ln = 0;
	oss_purl.ts_ln = 2;
	oss_purl.tmp = false;

	strcpy(oss_copyright.db, oss_db_name);
	strcpy(oss_copyright.table, "copyright");
	oss_copyright.key_ln = 16;
	oss_copyright.rec_ln = 0;
	oss_copyright.ts_ln = 2;
	oss_copyright.tmp = false;

	strcpy(oss_quality.db, oss_db_name);
	strcpy(oss_quality.table, "quality");
	oss_quality.key_ln = 16;
	oss_quality.rec_ln = 0;
	oss_quality.ts_ln = 2;
	oss_quality.tmp = false;

