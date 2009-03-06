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
#ifndef DB_ACCESS_H
#define DB_ACCESS_H
#include "global.h"
#include "db.h"

/** Start a new transaction.
 */
int
start_transaction (
   sqlite3_stmt *ps //!< Pointer to prepared statement.
);

/** Commit a transaction.
 */
int
commit (
   sqlite3_stmt *ps //!< Pointer to prepared statement.
);

/** Rollback a transaction
 */
int
rollback (
   sqlite3_stmt *ps //!< Pointer to prepared statement.
);

/** Get an address ID from a db table. 
 */
int
get_addr_id (
   sqlite3_stmt *ps, //!< Pointer to prepared statement.
   char *addr,       //!< Pointer to IPv6 address in presentation format.
   int *rows,        //!< Out: number of rows found (expected to be 0 or 1).
   sqlite_int64 *addr_id //!< Out: found address ID (if any).
);

/** Insert an unhandled packet in the db.
 */
int
insert_unhandled_packet (
   sqlite3_stmt *ps, //!< Pointer to prepared statement.
   sqlite_uint64 tid, //!< trace id corresponding to this packet.
   trace_t *t, //!< In: trace data.
   char *reason //!< In: Error string.
);


/** Insert a trace header into the db.
 */
int
insert_trace (
   sqlite3 *db, //!< Pointer to opened db.
   sqlite3_stmt *ps, //!< Pointer to prepared statement.
   trace_t *t, //!< In: trace data.
   sqlite_int64 *trace_id //!< In: trace data.
);

/** Insert a DNS header into the db.
 */
int
insert_dns_header (
   sqlite3_stmt *ps, //!< Pointer to prepared statement.
   sqlite_int64 trace_id, //!< Trace ID corresponding to this DNS header.
   ldns_pkt *pdns //!< In: DNS packet data.
);


 int
 insert_dns_q (
    sqlite3_stmt *ps, 
    int *paranum,
    ldns_rr_list *rr_list); 

/** Insert DNS RR data into the db.
 */
int
insert_dns_rr_data (
   sqlite3_stmt *ps, //!< Pointer to prepared statement.
   sqlite_int64 trace_id, //!< Trace ID corresponding to this DNS RR.
   uint16_t msg_id, //!< DNS message id.
   int rr_idx, //!< RR index.
   char *rr_tag, //!< RR tag, "QD", "NS", "AR", "AN".
   int rd_idx, //!< RR data index.
   ldns_rdf_type rd_type, //!< RR data type (from LDNS).
   char *rd_data //!< RR data.
);

/** Insert a DNS RR into the db.
 */
int
insert_dns_rr (
   sqlite3_stmt *ps, //!< Pointer to prepared statement.
   sqlite_int64 trace_id, //!< Trace ID corresponding to this RR.
   uint16_t msg_id, //!< DNS message id.
   ldns_rr *rr, //!< RR.
   int n, //!< RR number in DNS query/answer.
   char *rr_tag //!< "QD", "NS", "AN", or "AR".
);

/** Insert a DNS query header into the db.
 */
 int
 insert_dns_query_header (
    sqlite3_stmt *ps, //!< Pointer to prepared statement.
    int *parameternum, //!< In: Parametercount
    ldns_pkt *pdns //!< In: DNS packet data.
 );

/** Insert a DNS query into the db.
 */
 int
 insert_query (
	sqlite3_stmt *ps, 
	trace_t *t, 
	ldns_pkt *pdns);
 


#endif
