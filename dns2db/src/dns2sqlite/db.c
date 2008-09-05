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

static sql_stmt_t G_STMT [] = {
   {"BEGIN TRANSACTION", NULL},
   {"COMMIT", NULL},
   {"ROLLBACK", NULL},
   {"INSERT INTO TRACE (s,us,ether_type,protocol,src_addr,dst_addr,src_port) VALUES (:s,:us,:eth,:pro,:sa,:da,:por)", NULL},
   {"INSERT INTO UNHANDLED_PACKET VALUES (:tid,:pkt,:rsn)", NULL},
   {"INSERT INTO ADDR (addr) VALUES (:adr)", NULL},
   {"INSERT INTO DNS_HEADER VALUES (:tid,:mid,:qr,:aa,:tc,:rd,:cd,:ra,:ad,:oc,:rc,:qdc,:anc,:nsc,:arc)", NULL},
   {"INSERT INTO DNS_RR VALUES (:tid,:mid,:n,:rr,:lvl1,:lvl2,:rest,:rrt,:rrc,:ttl)", NULL},
   {"INSERT INTO DNS_RR_DATA VALUES (:tid,:mid,:rri,:rdi,:rdt,:rd)", NULL},
   {"SELECT ID FROM ADDR WHERE ADDR = :a", NULL}
};
#define NSTMT (sizeof G_STMT / sizeof G_STMT [0])

// === Local function prototypes ===============================================
int
copy_file (char *from, char *to, bool_t overwrite);

int
finalize_stmts (sql_stmt_t *s);

int
store_unhandled_packet (sql_stmt_t *s, sqlite_int64 trace_id, trace_t *t, char *reason);

int
store_dns_rr_data (
   sql_stmt_t *s, 
   sqlite_int64 trace_id, 
   sqlite_int64 msg_id, 
   int n, 
   int rdf_n,
   ldns_rdf *rdf
);

int
store_dns_rr (
   sql_stmt_t *s, 
   sqlite_int64 trace_id, 
   sqlite_int64 msg_id, 
   int n, 
   char *rr_tag, 
   ldns_rr *rr
);

int
store_dns_rr_list (
   sql_stmt_t *s, 
   sqlite_int64 trace_id, 
   sqlite_int64 msg_id, 
   char *rr_tag, 
   ldns_rr_list *rr_list
);

int
store_dns_packet (sql_stmt_t *s, sqlite_int64 trace_id, ldns_pkt *pdns);

int 
store_trace (sqlite3 *db, sql_stmt_t *s, trace_t *t, sqlite_int64 *trace_id);

// === Function implementations ================================================

// --- copy_file ---------------------------------------------------------------
int
copy_file (char *from, char *to, bool_t overwrite) {
   int c;
   FILE *f_fp;
   FILE *t_fp;
   
   // check if destination file exists and if it is ok to overwrite it.
   if ((t_fp = fopen (to, "rb")) != NULL) {
      if (overwrite) { 
         fclose (t_fp); 
      } 
      else {
         return FAILURE;
      }
   } 
         
   if ((f_fp = fopen (from, "rb")) == NULL) {
      perror (from);
      return FAILURE;
   }
   
   if ((t_fp = fopen (to, "wb")) == NULL) {
      perror (to);
      fclose (f_fp); // close the already opened 'from' file.
      return FAILURE;
   }
   
   while ((c = fgetc (f_fp)) != EOF) {
      fputc (c, t_fp);
   }
   
   fclose (f_fp);
   fflush (t_fp);
   fclose (t_fp);
   
   if (ferror (f_fp) && ferror (t_fp)) {
      fprintf (stderr, "Failed both reading from %s and writing to %s.\n", from, to);
      fprintf (stderr, "%s,%d,%s\n", __FILE__,__LINE__,strerror(errno));
      return FAILURE;
   }
   else if (ferror (f_fp)) {
      fprintf (stderr, "Failed while reading from %s.\n", from);
      fprintf (stderr, "%s,%d,%s\n", __FILE__,__LINE__,strerror(errno));
      return FAILURE;
   }
   else if (ferror (t_fp)) {
      fprintf (stderr, "Failed while writing to %s.\n", to);
      fprintf (stderr, "%s,%d,%s\n", __FILE__,__LINE__,strerror(errno));
      return FAILURE;
   }
   else {
      return SUCCESS;
   }
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
         fprintf (stderr, "Unable to prepare statement: %s\n", s->sql);
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
         fprintf (stderr, "Unable to finalize prepared statement: %s\n", s->sql);
         return FAILURE;
      }
   }
   return SUCCESS;
}


// --- store_unhandled_packet --------------------------------------------------
int
store_unhandled_packet (sql_stmt_t *s, sqlite_int64 trace_id, trace_t *t, char *reason) {
   
   if (!insert_unhandled_packet ((s + I_UNHAND)->pstmt, trace_id, t, reason)) {
      fprintf (stderr, "Could not insert into unhandled_packet table\n");
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
   int rdf_n,
   ldns_rdf *rdf
) {
   ldns_rdf_type rdf_t; 
   char * rdf_d;


   rdf_d = ldns_rdf2str (rdf);
   rdf_t = ldns_rdf_get_type (rdf);
   if (!insert_dns_rr_data ((s + I_DNS_RD)->pstmt, trace_id, msg_id, n, rdf_n, rdf_t, rdf_d)) {
      fprintf (stderr, "Could not insert into dns_rr_data table\n");
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
      fprintf (stderr, "Failed to store RR.\n");
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
         if (!store_dns_rr_data (s, trace_id, msg_id, n, rdf_n++, rdf)) {
            fprintf (stderr, "Failed to store RR data record.\n");
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
         fprintf (stderr, "Failed to store a %s RR\n", rr_tag);
         return FAILURE;
      }
      ldns_rr_free(rr);
   }
   return SUCCESS;
}


// --- store_dns_packet --------------------------------------------------------
int
store_dns_packet (sql_stmt_t *s, sqlite_int64 trace_id, ldns_pkt *pdns) {
   uint16_t msgid = ldns_pkt_id (pdns);
   

   if (!insert_dns_header ((s + I_DNS_H)->pstmt, trace_id, pdns)) {
      fprintf (stderr, "Failed to store DNS header.\n");
      return FAILURE;
   }
   else {
      if (!store_dns_rr_list (s, trace_id, msgid, "QD", ldns_pkt_question (pdns))) {
         fprintf (stderr, "Warning: could not store complete question section.\n");
      }
      if (!store_dns_rr_list (s, trace_id, msgid, "NS", ldns_pkt_answer (pdns))) {
         fprintf (stderr, "Warning: could not store complete answer section.\n");
      }
      if (!store_dns_rr_list (s, trace_id, msgid, "AR", ldns_pkt_authority (pdns))) {
         fprintf (stderr, "Warning: could not store complete authority section.\n");
      }
      if (!store_dns_rr_list (s, trace_id, msgid, "AN", ldns_pkt_additional (pdns))) {
         fprintf (stderr, "Warning: could not store complete additional section\n");
      }
   }
   return SUCCESS;
}


// --- store_trace -------------------------------------------------------------
int 
store_trace (sqlite3 *db, sql_stmt_t *s, trace_t *t, sqlite_int64 *trace_id) {
   int rows;
   sqlite_int64 src_addr_id;
   sqlite_int64 dst_addr_id;


   if (!get_addr_id ((s + S_ADDR_ID)->pstmt, trace_get_src_addr (t), &rows, &src_addr_id)) {
      // Technical failure (failed in some other way than not finding an id)
      fprintf (stderr, "Failed to get address id for %s\n", trace_get_src_addr (t));
      return FAILURE;
   }

   if (rows == 0) { // no address found, so insert it
      if (!insert_addr (db, (s + I_ADDR)->pstmt, trace_get_src_addr (t), &src_addr_id)) {
         fprintf (stderr, "Failed to insert address %s\n", trace_get_src_addr (t));
         return FAILURE;
      }
   }
      
   if (!get_addr_id ((s + S_ADDR_ID)->pstmt, trace_get_dst_addr (t), &rows, &dst_addr_id)) {
      // Technical failure (failed in some other way than not finding an id)
      fprintf (stderr, "Failed to get address id for %s\n", trace_get_dst_addr (t));
      return FAILURE;
   }
   
   if (rows == 0) { // no address found, so insert it
      if (!insert_addr (db, (s + I_ADDR)->pstmt, trace_get_dst_addr (t), &dst_addr_id)) {
         fprintf (stderr, "Failed to insert address %s\n", trace_get_dst_addr (t));
         return FAILURE;
      } 
   }
   
   if (!insert_trace (db, (s + I_TRACE)->pstmt, t, src_addr_id, dst_addr_id, trace_id)) {
      fprintf (stderr, "Could not insert into trace table.\n");
      return FAILURE;
   }
   return SUCCESS;
}


// --- store_to_db -------------------------------------------------------------
int
store_to_db (sqlite3 *db, sql_stmt_t *s, trace_t *t) {
   ldns_pkt *pdns_pkt;
   ldns_status ldns_rc;
   sqlite_int64 trace_id;
   int rc;

   // enhance sqlite performance at the expense of reliability.
   rc = sqlite3_exec (db, "pragma synchronous = OFF", NULL, NULL, NULL);
   rc = sqlite3_exec (db, "pragma temp_store = MEMORY", NULL, NULL, NULL);
   rc = sqlite3_exec (db, "pragma journal_mode = OFF", NULL, NULL, NULL);
   
   if (!store_trace (db, s, t, &trace_id)) {
      fprintf (stderr, "Failed to store trace.\n");
      return FAILURE;
   }
   
   if (trace_get_protocol (t) == IPPROTO_UDP || trace_get_protocol (t) == IPPROTO_TCP) {
      ldns_rc = ldns_wire2pkt (&pdns_pkt, trace_get_data (t), trace_get_length (t));

      if (ldns_rc != LDNS_STATUS_OK) {
         if (!store_unhandled_packet (s, trace_id, t, (char *)ldns_get_errorstr_by_id (ldns_rc))) { 
            return FAILURE;
         }
         return SUCCESS;
      }
      else {
         if (!store_dns_packet (s, trace_id, pdns_pkt)) {
            ldns_pkt_free (pdns_pkt);
            return FAILURE;
         }
         ldns_pkt_free (pdns_pkt);
         return SUCCESS;
      }
   } 
   else {
      if (!store_unhandled_packet (s, trace_id, t, "Unhandled protocol.")) { 
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
      fprintf (stderr, "Could not open database file: %s\n", filename);
      sqlite3_close (*db);
      return FAILURE;
   }
   
   return SUCCESS;
}

// --- create_db ---------------------------------------------------------------
int 
create_db (char *template, char *dt_filename, bool_t overwrite, sqlite3 **db) {
   if (!create_db_from_template (template, dt_filename, overwrite, db)) {
      fprintf (stderr, "Failed to create database from template %s.\n", template);
      return FAILURE;
   }
   
   return SUCCESS;
}

// --- create_db_from_template -------------------------------------------------
int
create_db_from_template (char *template, char *filename, bool_t overwrite, sqlite3 **db) {
   if (!copy_file (template, filename, overwrite)) {
      fprintf (stderr, "Failed to copy template db from %s to %s.\n", template, filename);
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
