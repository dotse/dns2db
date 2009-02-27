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

#include "db_access.h"

// === Local function prototypes ===============================================
void
split_dname3 (char **rdname3, ldns_rr *rr);

// === Function implementations ================================================

// --- split_dname3 ------------------------------------------------------------
// Split a dname into three parts; tld, subdom, and host. Missing parts are
// substituted by a single '.'.
void
split_dname3 (char **rdname3, ldns_rr *rr) {
   ldns_rdf *rowner = NULL;
   ldns_rdf *label = NULL;
   ldns_rdf *tmp = NULL;
   uint8_t n = 0;
   uint8_t i = 0;
   
   rowner = ldns_dname_reverse (ldns_rr_owner (rr));
   if (rowner == NULL) return;
   
   label = ldns_dname_label (rowner, 0);
   n = ldns_dname_label_count (rowner);

   tmp = rowner;
   while (i < 2 && i <= n) {
      rdname3 [i] = label == NULL ? strdup (".") : ldns_rdf2str (label);
      if (label != NULL) {ldns_rdf_deep_free (label);}
      tmp = ldns_dname_left_chop (rowner);
      ldns_rdf_deep_free (rowner);
      label = tmp == NULL ? NULL : ldns_dname_label (tmp, 0);
      rowner = tmp;
      i++;
   }
   rdname3 [2] = rowner == NULL ? strdup (".") : ldns_rdf2str (rowner);
   ldns_rdf_deep_free (rowner);
   if (label != NULL) {ldns_rdf_deep_free (label);}
}

// --- start_transaction -------------------------------------------------------
int
start_transaction (sqlite3_stmt *ps) {
   int rc;
   
   rc = sqlite3_reset (ps);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not reset statement.");
      return FAILURE;
   }
   
   rc = sqlite3_clear_bindings (ps);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not clear statement bindings.");
      return FAILURE;
   }
   
   rc = sqlite3_step (ps);
   if (rc != SQLITE_DONE) {
      d2log (LOG_ERR|LOG_USER, "Could not start transaction.");
      return FAILURE;
   }
   return SUCCESS;
}

// --- commit ------------------------------------------------------------------
int
commit (sqlite3_stmt *ps) {
   int rc;
   
   rc = sqlite3_reset (ps);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not reset statement.");
      return FAILURE;
   }
   
   rc = sqlite3_clear_bindings (ps);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not clear statement bindings.");
      return FAILURE;
   }
   
   rc = sqlite3_step (ps);
   if (rc != SQLITE_DONE) {
      d2log (LOG_ERR|LOG_USER, "Could not commit.");
      return FAILURE;
   }
   return SUCCESS;
}

// --- rollback ----------------------------------------------------------------
int
rollback (sqlite3_stmt *ps) {
   int rc;
   
   rc = sqlite3_reset (ps);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not reset statement.");
      return FAILURE;
   }
   
   rc = sqlite3_clear_bindings (ps);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not clear statement bindings.");
      return FAILURE;
   }
   
   rc = sqlite3_step (ps);
   if (rc != SQLITE_DONE) {
      d2log (LOG_ERR|LOG_USER, "Could not rollback.");
      return FAILURE;
   }
   return SUCCESS;
}


// --- get_addr_id -------------------------------------------------------------
int
get_addr_id (sqlite3_stmt *ps, char *addr, int *rows, sqlite_int64 *addr_id) {
   int rc;
   
   rc = sqlite3_reset (ps);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not reset statement.");
      return FAILURE;
   }
   
   rc = sqlite3_clear_bindings (ps);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not clear statement bindings.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_text (ps, 1, addr, -1, SQLITE_TRANSIENT);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   *rows = 0;
   
   while (*rows < 2 && (rc = sqlite3_step (ps)) == SQLITE_ROW) {
      *addr_id = sqlite3_column_int64 (ps, 0);
      ++(*rows);
   }
   
   return rc == SQLITE_DONE ? SUCCESS : FAILURE;
}


// --- insert_unhandled_packet -------------------------------------------------
int
insert_unhandled_packet (
   sqlite3_stmt *ps, 
   sqlite_uint64 tid, 
   trace_t *t, 
   char *reason
) {
   int rc;
   
   rc = sqlite3_reset (ps);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not reset statement.");
      return FAILURE;
   }
   
   rc = sqlite3_clear_bindings (ps);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not clear statement bindings.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int64 (ps, 1, tid);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_blob (ps, 2, t, sizeof (*t), SQLITE_TRANSIENT);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_text (ps, 3, reason, -1, SQLITE_TRANSIENT);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_step (ps);
   if (rc != SQLITE_DONE) {
      d2log (LOG_ERR|LOG_USER, "Could not insert data in table 'unhandled_packet'.");
      return FAILURE;
   }
   
   return SUCCESS;
}

// --- insert_addr -------------------------------------------------------------
int
insert_addr (sqlite3 *db, sqlite3_stmt *ps, char *addr, sqlite_int64 *addr_id) {
   int rc;
   
   rc = sqlite3_reset (ps);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not reset statement.");
      return FAILURE;
   }
   
   rc = sqlite3_clear_bindings (ps);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not clear statement bindings.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_text (ps, 1, addr, -1, SQLITE_TRANSIENT);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_step (ps);
   if (rc != SQLITE_DONE) {
      d2log (LOG_ERR|LOG_USER, "Could not insert data in table 'addr'.");
      return FAILURE;
   }
   
   *addr_id = sqlite3_last_insert_rowid (db);
   
   return SUCCESS;
}

// --- insert_trace ------------------------------------------------------------
int
insert_trace (
   sqlite3 *db, 
   sqlite3_stmt *ps, 
   trace_t *t, 
   sqlite_int64 src_addr_id, 
   sqlite_int64 dst_addr_id,
   sqlite_int64 *trace_id 
) {
   int rc;
   
   rc = sqlite3_reset (ps);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not reset statement.");
      return FAILURE;
   }
   
   rc = sqlite3_clear_bindings (ps);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not clear statement bindings.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 1, trace_get_seconds (t));
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 2, trace_get_micro_seconds (t));
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 3, trace_get_ethertype (t));
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 4, trace_get_protocol (t));
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int64 (ps, 5, src_addr_id);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int64 (ps, 6, dst_addr_id);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 7, trace_get_port (t)); 
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_step (ps);
   if (rc != SQLITE_DONE) {
      d2log (LOG_ERR|LOG_USER, "Could not insert data in table 'trace (%d)'.", rc);
      return FAILURE;
   }
   
   *trace_id = sqlite3_last_insert_rowid (db);
   return SUCCESS;
}  


// --- insert_dns_header -------------------------------------------------------
int
insert_dns_header (sqlite3_stmt *ps, sqlite_int64 trace_id, ldns_pkt *pdns) {
   int rc;
   
   rc = sqlite3_reset (ps);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not reset statement.");
      return FAILURE;
   }
   
   rc = sqlite3_clear_bindings (ps);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not clear statement bindings.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int64 (ps, 1, trace_id);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 2, ldns_pkt_id (pdns));
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 3, ldns_pkt_qr (pdns)); 
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 4, ldns_pkt_aa (pdns));
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 5, ldns_pkt_tc (pdns));
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 6, ldns_pkt_rd (pdns));
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 7, ldns_pkt_cd (pdns));
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 8, ldns_pkt_ra (pdns));
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 9, ldns_pkt_ad (pdns));
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 10, ldns_pkt_get_opcode (pdns));
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 11, ldns_pkt_get_rcode (pdns));
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   

   bool edns = ldns_pkt_edns (pdns);
   rc = sqlite3_bind_int (ps, 12, edns);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   if (edns)
   {
      rc = sqlite3_bind_int (ps, 13, ldns_pkt_edns_do (pdns));
      if (rc != SQLITE_OK) {
         d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
         return FAILURE;
      }
      
      rc = sqlite3_bind_int (ps, 14, ldns_pkt_edns_extended_rcode (pdns));
      if (rc != SQLITE_OK) {
         d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
         return FAILURE;
      }
      
      rc = sqlite3_bind_int (ps, 15, ldns_pkt_edns_version (pdns));
      if (rc != SQLITE_OK) {
         d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
         return FAILURE;
      }
      
      rc = sqlite3_bind_int (ps, 16, ldns_pkt_edns_z (pdns) & 0x7fff);
      if (rc != SQLITE_OK) {
         d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
         return FAILURE;
      }
      
   
   }
   else   
   {
      rc = sqlite3_bind_int (ps, 13, 0);
      if (rc != SQLITE_OK) {
         d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
         return FAILURE;
      }
      rc = sqlite3_bind_int (ps, 14, 0);
      if (rc != SQLITE_OK) {
         d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
         return FAILURE;
      }
      rc = sqlite3_bind_int (ps, 15, 0);
      if (rc != SQLITE_OK) {
         d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
         return FAILURE;
      }
      rc = sqlite3_bind_int (ps, 16, 0);
      if (rc != SQLITE_OK) {
         d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
         return FAILURE;
      }
   }
   
   rc = sqlite3_bind_int (ps, 17, ldns_pkt_qdcount (pdns));
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 18, ldns_pkt_ancount (pdns));
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 19, ldns_pkt_nscount (pdns));
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 20, ldns_pkt_arcount (pdns));
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_step (ps);
   if (rc != SQLITE_DONE) {
      d2log (LOG_ERR|LOG_USER, "Could not insert data in table 'dns_header (%d)'.", rc);
      return FAILURE;
   }
   
   return SUCCESS;
}

// --- insert_dns_rr_data ------------------------------------------------------
int
insert_dns_rr_data (
   sqlite3_stmt *ps, 
   sqlite_int64 trace_id, 
   uint16_t msg_id, 
   int rr_idx, 
   char *rr_tag,
   int rd_idx, 
   ldns_rdf_type rd_type, 
   char *rd_data
) {
   int rc;
   rc = sqlite3_reset (ps);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not reset statement.");
      return FAILURE;
   }
   
   rc = sqlite3_clear_bindings (ps);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not clear statement bindings.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int64 (ps, 1, trace_id);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 2, msg_id);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 3, rr_idx);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_text (ps, 4, rr_tag, -1, SQLITE_TRANSIENT);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 5, rd_idx);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 6, rd_type);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_text (ps, 7, rd_data, -1, SQLITE_TRANSIENT);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_step (ps);
   if (rc != SQLITE_DONE) {
      d2log (LOG_ERR|LOG_USER, "Could not insert data in table 'dns_rr_data (%d)'.", rc);
      return FAILURE;
   }
   
   return SUCCESS;
}


// --- insert_dns_rr -----------------------------------------------------------
int
insert_dns_rr (
   sqlite3_stmt *ps, 
   sqlite_int64 trace_id, 
   uint16_t msg_id, 
   ldns_rr *rr, 
   int n, 
   char *rr_tag
) {
   int rc;
   char * rdname3 [] = {NULL, NULL, NULL};
   
   rc = sqlite3_reset (ps);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not reset statement.");
      return FAILURE;
   }
   
   rc = sqlite3_clear_bindings (ps);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not clear statement bindings.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int64 (ps, 1, trace_id);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 2, msg_id);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 3, n);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_text (ps, 4, rr_tag, -1, SQLITE_TRANSIENT);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }

   split_dname3 (rdname3, rr);
   
   rc = sqlite3_bind_text (ps, 5, rdname3 [0], -1, SQLITE_TRANSIENT);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      XFREE(rdname3[0]);
      XFREE(rdname3[1]);
      XFREE(rdname3[2]);
      return FAILURE;
   }

   rc = sqlite3_bind_text (ps, 6, rdname3 [1], -1, SQLITE_TRANSIENT);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      XFREE(rdname3[0]);
      XFREE(rdname3[1]);
      XFREE(rdname3[2]);
      return FAILURE;
   }

   rc = sqlite3_bind_text (ps, 7, rdname3 [2], -1, SQLITE_TRANSIENT);
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      XFREE(rdname3[0]);
      XFREE(rdname3[1]);
      XFREE(rdname3[2]);
      return FAILURE;
   }
   
   XFREE(rdname3[0]);
   XFREE(rdname3[1]);
   XFREE(rdname3[2]);
   
   rc = sqlite3_bind_int (ps, 8, ldns_rr_get_type (rr));
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 9, ldns_rr_get_class (rr));
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_bind_int (ps, 10, ldns_rr_ttl (rr));
   if (rc != SQLITE_OK) {
      d2log (LOG_ERR|LOG_USER, "Could not bind value to parameter.");
      return FAILURE;
   }
   
   rc = sqlite3_step (ps);
   if (rc != SQLITE_DONE) {
      return FAILURE;
   }
   
   return SUCCESS;
}
