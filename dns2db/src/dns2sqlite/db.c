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
#include "db.h"

/*! \ingroup dns2sqlite */ 
/*@{*/


static sql_stmt_t G_STMT [] = {
   {"BEGIN TRANSACTION", NULL},
   {"COMMIT", NULL},
   {"ROLLBACK", NULL},
   {"INSERT INTO TRACE (s,us,ether_type,protocol,src_addr,dst_addr,src_port) VALUES (:s,:us,:eth,:pro,:sa,:da,:por)", NULL},
   {"INSERT INTO UNHANDLED_PACKET VALUES (:tid,:pkt,:rsn)", NULL},
   {"INSERT INTO DNS_HEADER VALUES (:tid,:mid,:qr,:aa,:tc,:rd,:cd,:ra,:ad,:oc,:rc,:edns0,:do,:extended_rcode,:version,:z,:qdc,:anc,:nsc,:arc)", NULL},
   {"INSERT INTO DNS_RR VALUES (:tid,:mid,:n,:rr,:lvl1,:lvl2,:rest,:rrt,:rrc,:ttl)", NULL},
   {"INSERT INTO DNS_RR_DATA VALUES (:tid,:mid,:rri,:rrt,:rdi,:rdt,:rd)", NULL},
   {"INSERT INTO Q VALUES "
         "(:null,:s,:us,:eth,:pro,:sa,:da,:por," //8
         ":mid,:qr,:aa,:tc,:rd,:cd,:ra,:ad,:oc,:rc," //10+8
         ":edns0,:do,:extended_rcode,:version,:z,"  //15+8
         ":qdc,:anc,:nsc,:arc,"              //19+8
         ":lvl1,:lvl2,:rest,:rrt,:rrc"       //5+19+8
         ")", NULL}
};
#define NSTMT (sizeof G_STMT / sizeof G_STMT [0])

// === Local function prototypes ===============================================

/** Copy a file from "from" to "to". If "overwrite" is "TRUE" then overwrite any
 *  existing destination file.
 */
int
copy_file (FILE *from_file, char *from, char *to, bool_t overwrite);

/** Finalize prepared statements.
 */
int
finalize_stmts (sql_stmt_t *s);

/** Store unhandled packets, i.e. non DNS messages, separately in the database.
 */
int
store_unhandled_packet (sqlite3 *db, sql_stmt_t *s, sqlite_int64 trace_id, trace_t *t, char *reason);

/** Store an RR DATA section in the database.
 */
int
store_dns_rr_data (
   sql_stmt_t *s, 
   sqlite_int64 trace_id, 
   sqlite_int64 msg_id, 
   int n, 
   char *rr_tag,
   int rdf_n,
   ldns_rdf *rdf
);

/** Store an RR record in the database.
 */
int
store_dns_rr (
   sql_stmt_t *s, 
   sqlite_int64 trace_id, 
   sqlite_int64 msg_id, 
   int n, 
   char *rr_tag, 
   ldns_rr *rr
);

/** Store a list of RR records in the database.
 */
int
store_dns_rr_list (
   sql_stmt_t *s, 
   sqlite_int64 trace_id, 
   sqlite_int64 msg_id, 
   char *rr_tag, 
   ldns_rr_list *rr_list
);

/** Store a presumed DNS message in the database. If the DNS message can't be
 *  parsed as a proper DNS message then it will be stored unparsed as an 
 *  "unhandled packet".
 */
int
store_dns_query_packet (sql_stmt_t *s,  trace_t *t, ldns_pkt *pdns);

int
store_dns_packet (sqlite3 *db, sql_stmt_t *s, sqlite_int64 trace_id, trace_t *t, ldns_pkt *pdns);

/** Store general information about the packet trace, i.e. timestamp, IP-
 *  addresses, protocol, and port.
 */
int
store_trace (sqlite3 *db, sql_stmt_t *s, trace_t *t, sqlite_int64 *trace_id);

// === Function implementations ================================================

// --- copy_file ---------------------------------------------------------------
int
copy_file (FILE *f_fp, char *from, char *to, bool_t overwrite) {
   int c;
   FILE *t_fp;
   int result = SUCCESS;

   // check if destination file exists and if it is ok to overwrite it.
   if ((t_fp = fopen (to, "rb")) != NULL) {
      if (overwrite) { 
         fclose (t_fp); 
      } 
      else {
         return FAILURE;
      }
   }


   if ((t_fp = fopen (to, "wb")) == NULL) {
      perror (to);
      fclose (f_fp); // close the already opened 'from' file.
      return FAILURE;
   }

   while ((c = fgetc (f_fp)) != EOF) {
      fputc (c, t_fp);
   }

   fflush (t_fp);

   if (ferror (f_fp) && ferror (t_fp)) {
      d2log (
         LOG_ERR|LOG_USER, 
         "Failed both reading from %s and writing to %s. Error: %s", from, to, strerror (errno));
      result = FAILURE;
   }
   else if (ferror (f_fp)) {
      d2log (LOG_ERR|LOG_USER, "Failed while reading from %s. Error: %s", from, strerror (errno));
      result = FAILURE;
   }
   else if (ferror (t_fp)) {
      d2log (LOG_ERR|LOG_USER, "Failed while writing to %s.", to, strerror (errno));
      result = FAILURE;
   }

   fclose (f_fp);
   fclose (t_fp);

   return result;
}


// --- prepare_stmts -----------------------------------------------------------
int
prepare_stmts (sqlite3 *db, sql_stmt_t **base) {
   int rc;
   const char *tail;
   sql_stmt_t *s = G_STMT;

   *base = s;

   for (unsigned int i = 0; i < NSTMT; ++i, s++) {
      rc  = sqlite3_prepare_v2 (db, s->sql, strlen (s->sql), &s->pstmt, &tail);

      if (rc != SQLITE_OK) {
         d2log (LOG_ERR|LOG_USER, "Unable to prepare statement: %s", s->sql);
         return FAILURE;
      }
   }
   return SUCCESS;
}


// --- finalize_stmts ----------------------------------------------------------
int
finalize_stmts (sql_stmt_t *s) {
   int rc;

   for (unsigned int i = 0; i < NSTMT; ++i, s++) {
      rc = sqlite3_finalize (s->pstmt);

      if (rc != SQLITE_OK) {
         d2log (LOG_ERR|LOG_USER, "Unable to finalize prepared statement: %s", s->sql);
         return FAILURE;
      }
   }
   return SUCCESS;
}


// --- store_unhandled_packet --------------------------------------------------
int
store_unhandled_packet (sqlite3 *db, sql_stmt_t *s, sqlite_int64 trace_id, trace_t *t, char *reason) {

   if (!store_trace (db, s, t, &trace_id)) {
      d2log (LOG_ERR|LOG_USER, "Failed to store trace.");
      return FAILURE;
   }
   if (!insert_unhandled_packet ((s + I_UNHAND)->pstmt, trace_id, t, reason)) {
      d2log (LOG_ERR|LOG_USER, "Could not insert into unhandled_packet table");
      return FAILURE;
   }
   return SUCCESS;
}


// --- store_dns_rr_data -------------------------------------------------------
int
store_dns_rr_data (
   sql_stmt_t *s, 
   sqlite_int64 trace_id, 
   sqlite_int64 msg_id, 
   int n, 
   char *rr_tag,
   int rdf_n,
   ldns_rdf *rdf
) {
   ldns_rdf_type rdf_t;
   char *rdf_d;


   rdf_d = ldns_rdf2str (rdf);
   rdf_t = ldns_rdf_get_type (rdf);
   if (!insert_dns_rr_data ((s + I_DNS_RD)->pstmt, trace_id, msg_id, n, rr_tag, rdf_n, rdf_t, rdf_d)) {
      d2log (LOG_ERR|LOG_USER, "Could not insert into dns_rr_data table");
      XFREE(rdf_d);
      return FAILURE;
   }

   XFREE(rdf_d);
   return SUCCESS;
}


// --- store_dns_rr ------------------------------------------------------------
int
store_dns_rr (
   sql_stmt_t *s,
   sqlite_int64 trace_id,
   sqlite_int64 msg_id,
   int n,
   char *rr_tag,
   ldns_rr *rr
) {
   int rdf_n = 0;
   ldns_rdf *rdf;


   if (!insert_dns_rr ((s + I_DNS_RR)->pstmt, trace_id, msg_id, rr, n, rr_tag)) {
      d2log (LOG_ERR|LOG_USER, "Failed to store RR.");
      return FAILURE;
   } 
   else {

      // NB: Workaround for ldns-bug in ldns_rr_pop_rdf. The latter uses
      // rd_count directly as index into _rdata_fields and thus reads from 
      // one position beyond the array.
      // 2008-07-25: Fix committed in ldns trunk revision 2692, and slated for 
      // the next release (communication from Jelte Jansen @ nlnetlabs).
      // "Next relese" > ldns-1.3.0.
      for (unsigned int i = 0; i < ldns_rr_rd_count (rr); ++i) {
         rdf = rr->_rdata_fields [i];
         if (!store_dns_rr_data (s, trace_id, msg_id, n, rr_tag, rdf_n++, rdf)) {
            d2log (LOG_ERR|LOG_USER, "Failed to store RR data record.");
            return FAILURE;
         }
      }
   }
      
   return SUCCESS;
}


// --- store_dns_rr_list -------------------------------------------------------
int
store_dns_rr_list (
   sql_stmt_t *s, 
   sqlite_int64 trace_id, 
   sqlite_int64 msg_id, 
   char *rr_tag, 
   ldns_rr_list *rr_list
) {
   int n = 0;
   ldns_rr *rr;

   while ((rr = ldns_rr_list_pop_rr (rr_list)) != NULL) {
      if (!store_dns_rr (s, trace_id, msg_id, n++, rr_tag, rr)) {
         d2log (LOG_ERR|LOG_USER, "Failed to store a %s RR", rr_tag);
         return FAILURE;
      }
      ldns_rr_free(rr);
   }
   return SUCCESS;
}

// --- store_dns_query_packet --------------------------------------------------------
int
store_dns_query_packet (sql_stmt_t *s,  trace_t *t, ldns_pkt *pdns) {
   uint16_t msgid = ldns_pkt_id (pdns);

   if (!insert_query ((s + I_QUERY)->pstmt, t, pdns)) {
      d2log (LOG_ERR|LOG_USER, "Could not insert into trace table.");
      return FAILURE;
   }
   return SUCCESS;

}



// --- store_dns_packet --------------------------------------------------------
int
store_dns_packet (sqlite3 *db, sql_stmt_t *s, sqlite_int64 trace_id, trace_t *t, ldns_pkt *pdns) {
   uint16_t msgid = ldns_pkt_id (pdns);

   if (!store_trace (db, s, t, &trace_id)) {
      d2log (LOG_ERR|LOG_USER, "Failed to store trace.");
      return FAILURE;
   }

   if (!insert_dns_header ((s + I_DNS_H)->pstmt, trace_id, pdns)) {
      d2log (LOG_ERR|LOG_USER, "Failed to store DNS header.");
      return FAILURE;
   }
   else {
      if (!store_dns_rr_list (s, trace_id, msgid, "QD", ldns_pkt_question (pdns))) {
         d2log (LOG_WARNING|LOG_USER, "Warning: could not store complete question section.");
      }
      if (!store_dns_rr_list (s, trace_id, msgid, "NS", ldns_pkt_answer (pdns))) {
         d2log (LOG_WARNING|LOG_USER, "Warning: could not store complete answer section.");
      }
      if (!store_dns_rr_list (s, trace_id, msgid, "AR", ldns_pkt_authority (pdns))) {
         d2log (LOG_WARNING|LOG_USER, "Warning: could not store complete authority section.");
      }
      if (!store_dns_rr_list (s, trace_id, msgid, "AN", ldns_pkt_additional (pdns))) {
         d2log (LOG_WARNING|LOG_USER, "Warning: could not store complete additional section");
      }
   }
   return SUCCESS;
}


// --- store_trace -------------------------------------------------------------
int 
store_trace (sqlite3 *db, sql_stmt_t *s, trace_t *t, sqlite_int64 *trace_id) {
   
   if (!insert_trace (db, (s + I_TRACE)->pstmt, t, trace_id)) {
      d2log (LOG_ERR|LOG_USER, "Could not insert into trace table.");
      return FAILURE;
   }
   return SUCCESS;
}


// --- store_to_db -------------------------------------------------------------
int
store_to_db (sqlite3 *db, sql_stmt_t *s, trace_t *t, bool_t only_q, bool_t only_r) {
   ldns_pkt *pdns_pkt;
   ldns_status ldns_rc;
   sqlite_int64 trace_id;
   int res = SUCCESS;

   
   if (trace_get_protocol (t) == IPPROTO_UDP || trace_get_protocol (t) == IPPROTO_TCP) {
      ldns_rc = ldns_wire2pkt (&pdns_pkt, trace_get_data (t), trace_get_length (t));

      if (ldns_rc != LDNS_STATUS_OK) {
         if (!store_unhandled_packet (db, s, trace_id, t, (char *)ldns_get_errorstr_by_id (ldns_rc))) { 
            return FAILURE;
         }
         return SUCCESS;
      }
      else {


         if (ldns_pkt_qr(pdns_pkt) == 0) // is packet a question ?
         {
            if (!only_r)
               res = store_dns_query_packet (s, t, pdns_pkt);
         }
         else
         {
            if (!only_q)
               res = store_dns_packet (db, s, trace_id, t, pdns_pkt);
         }
         ldns_pkt_free (pdns_pkt);
         return res;
      }
   } 
   else {
      if (!store_unhandled_packet (db, s, trace_id, t, "Unhandled protocol.")) { 
         return FAILURE;
      }
   }
   return SUCCESS;
}

// --- isdbopen ----------------------------------------------------------------
int 
isdbopen (sqlite3 *db) {
   return db != NULL;
}

// --- open_db -----------------------------------------------------------------
int
open_db (char *filename, sqlite3 **db) {
   int rc;
   FILE *fp;
   
   // simplistic test whether the database file exists
   fp = fopen (filename, "rw");
   if (!fp) {
      return FAILURE;
   }
   fclose (fp);
   
   rc = sqlite3_open (filename, db);
      
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not open database file: %s", filename);
      sqlite3_close (*db);
      return FAILURE;
   }
   // enhance sqlite performance at the expense of reliability.
   rc = sqlite3_exec (*db, "pragma synchronous = OFF", NULL, NULL, NULL);
   rc = sqlite3_exec (*db, "pragma temp_store = MEMORY", NULL, NULL, NULL);
   rc = sqlite3_exec (*db, "pragma journal_mode = OFF", NULL, NULL, NULL);
   
   return SUCCESS;
}

// --- create_db ---------------------------------------------------------------
int
create_db (FILE *template_file, char *template, char *dt_filename, bool_t overwrite, sqlite3 **db) {
   if (!create_db_from_template (template_file, template, dt_filename, overwrite, db)) {
      d2log (LOG_ERR|LOG_USER, "Failed to create database from template %s.", template);
      return FAILURE;
   }
   
   return SUCCESS;
}

// --- create_db_from_template -------------------------------------------------
int
create_db_from_template (FILE *template_file, char *template, char *filename, bool_t overwrite, sqlite3 **db) {
    if (!copy_file (template_file,template, filename, overwrite)) {
      d2log (LOG_ERR|LOG_USER, "Failed to copy template db from %s to %s.", template, filename);
      return FAILURE;
   }

   return open_db (filename, db);
}

// --- close_db ----------------------------------------------------------------
int
close_db (sqlite3 *db) {
   finalize_stmts (G_STMT);
   sqlite3_close (db);
   return SUCCESS;
}

/*}@*/
