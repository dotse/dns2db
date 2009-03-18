/*! \file */ 
/*
 * Copyright (c) 2007 .SE (The Internet Infrastructure Foundation).
 *                  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * ##################################################################### 
 *
 */
#ifndef DB_H
#define DB_H
#include "global.h"
#include "db_access.h"

enum {
   BEGIN_TRANS, 
   COMMIT,
   ROLLBACK,
   I_TRACE, 
   I_UNHAND, 
   I_DNS_H, 
   I_DNS_RR, 
   I_DNS_RD, 
   I_QUERY
};

struct sql_stmt {
   char *sql;
   sqlite3_stmt *pstmt;
};
typedef struct sql_stmt sql_stmt_t;

/** Is the database pointed to by the argument "db" open.
 */
int 
isdbopen (sqlite3 *db);

/** Open the database indicated by "filename" and set "db" to point to the opened
 * database instance.
 */
int
open_db (char *filename, sqlite3 **db);

/** Create a new database with "filename" from the given template.
 */
int
create_db (FILE *template_file, char *template, char *filename, bool_t overwrite, sqlite3 **db);

/** Prepare the SQL statements in "s" to be used with the database instance
 * pointed to by "db".
 */
int
prepare_stmts (sqlite3 *db, sql_stmt_t **s);

/** Finalize any prepared statements and close the database instance pointed to
 * by "db".
 */
int
close_db (sqlite3 *db);

/** Store the trace record pointed to by "ptd" in "db" using the prepared 
 * statements in "ps".
 */
int
store_to_db (sqlite3 *db, sql_stmt_t *ps, trace_t *ptd, bool_t only_q, bool_t only_r);

/** Create a new database from a given template.
 */
int
create_db_from_template (FILE *template_file, char *template, char *filename, bool_t overwrite, sqlite3 **db);

#endif
