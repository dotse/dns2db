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

#include "tcp.h"

static list_t tcp_stream;


// --- tcp_stream_destructor ---------------------------------------------------
void
tcp_stream_destructor (void *n) {
   assert (n != NULL);
	tcp_stream_t *st = (tcp_stream_t *) list_head ((list_t) n);
   list_delete (st->seg_list);
   st->seg_list = NULL;
}


// --- tcp_stream_eq -----------------------------------------------------------
Bool
tcp_stream_eq (void *st_1, void *st_2) {
   tcp_stream_t *s1 = (tcp_stream_t *) st_1;
   tcp_stream_t *s2 = (tcp_stream_t *) st_2;

   return IN6_ARE_ADDR_EQUAL(s1->src_ip, s2->src_ip) 
      && IN6_ARE_ADDR_EQUAL(s1->dst_ip, s2->dst_ip) 
      && s1->src_port == s2->src_port 
      && s1->dst_port == s2->dst_port;
}


// --- tcp_make_stream ---------------------------------------------------------
tcp_stream_t *
tcp_make_stream (in6addr_t *s, in6addr_t *d, uint16_t sp, uint16_t dp) {
   tcp_stream_t *st = (tcp_stream_t *) calloc (1, sizeof (tcp_stream_t));
   assert (st != NULL);

   st->src_ip = s;
   st->dst_ip = d;
   st->src_port = sp;
   st->dst_port = dp;
   st->seg_list = NULL;
   return st;
}


// --- tcp_delete_stream_aux ---------------------------------------------------
list_t
tcp_delete_stream_aux (list_t h, list_t curr, tcp_stream_t *st) {
   assert (st != NULL);
   list_t next;
   list_t prev = list_get_prev (curr);

   if (list_is_empty (curr) != FALSE) {
      return h;
   }
   else if (tcp_stream_eq (st, list_head (curr)) != FALSE) {
      if (h == curr) {
         return list_delete_head (curr);
      }
      else {
         next = list_delete_head (curr);
         list_set_next (prev, next);
         list_set_prev (next, prev);
         return h;
      }
   }
   else {
      return tcp_delete_stream_aux (h, list_tail (curr), st);
   }
}

// --- tcp_delete_stream -------------------------------------------------------
void
tcp_delete_stream (tcp_stream_t *st) {
   assert (st != NULL);
//   fprintf (stderr, "<- %p ->\\n", (void *) st); 
   list_delete (st->seg_list);
   st->seg_list = NULL;

   tcp_stream = tcp_delete_stream_aux (tcp_stream, tcp_stream, st);
}


// --- tcp_concat_seg_list -----------------------------------------------------
uint8_t *
tcp_concat_seg_list (list_t list, uint8_t *buf, uint32_t *buf_size) {
   size_t s;
   if (list_is_empty (list) != FALSE) {
      return buf;
   }
   else {
      s = tcp_seg_get_datasize (list_head (list));
      if (s > 0) {
         *buf_size += s;
         buf = realloc (buf, *buf_size);
         assert (buf != NULL);
         memcpy (buf + *buf_size - s, tcp_seg_get_data (list_head (list)), s);
      }
      return tcp_concat_seg_list (list_tail (list), buf, buf_size);
   }
}


// --- tcp_get_stream_data -----------------------------------------------------
uint8_t *
tcp_get_stream_data (tcp_stream_t *st, uint32_t *rest) {
   assert (st != NULL);
   
   uint8_t *buf;
   
   buf = (uint8_t *) calloc (1, 0);
   assert (buf != NULL);

   *rest = 0;
   return tcp_concat_seg_list (st->seg_list, buf, rest);
}


// --- tcp_lookup --------------------------------------------------------------
tcp_stream_t *
tcp_lookup (
   in6addr_t *src_ip, 
   in6addr_t *dst_ip,
   uint16_t src_port,
   uint16_t dst_port
) {
   list_t n;
   tcp_stream_t *st = tcp_make_stream (src_ip, dst_ip, src_port, dst_port);
   n = list_find (st, tcp_stream);
   XFREE(st);
   return n == NULL ? NULL : (tcp_stream_t *) list_head (n);
}


// --- tcp_add_segment_aux -----------------------------------------------------
list_t
tcp_add_segment_aux (list_t h, list_t curr, seg_t *s) {
   assert (s != NULL);

   list_t n;
   list_data_t s_data;

   s_data.data = s;
   s_data.size = sizeof (seg_t);
   s_data.de_fn = tcp_seg_destructor;
   s_data.eq_fn = tcp_seg_eq;

   n = list_prepend (&s_data, NULL);
   assert (n != NULL);
   
   if (list_is_empty (curr) != FALSE) {
      return n;
   }
   else if (list_is_empty (list_get_next (curr)) != FALSE) {
      list_set_prev (n, curr);
      list_set_next (curr, n);
      return h;
   }
   else if (tcp_seg_eq (s, list_head (curr))) {
      list_replace (curr, n);
      list_delete_head (curr);
      return list_is_empty (list_get_prev (n)) != FALSE ? n : h;
   }
   else {
      return tcp_add_segment_aux (h, list_get_next (h), s);
   }
}


// --- tcp_add_segment ---------------------------------------------------------
void
tcp_add_segment (tcp_stream_t *st, libtrace_tcp_t *tcp, uint32_t *rest) {
   seg_t *s;
   uint8_t *p;
   size_t len = *rest - tcp->doff * 4;

   // check for no packet data or a truncated header with no data. The later
   // will be negative if size_t is signed and greater than 64K if size_t is
   // unsigned. 64K is the maximum size of a single tcp segment according to
   // the TCP specification.
   if (len <= 0 || len > 65535) {
      return;
   }

   p = (uint8_t *) trace_get_payload_from_tcp (tcp, rest); // p is freed by libtrace
   *rest = len;

   s = tcp_seg_make_seg (ntohs (tcp->seq), p, len);
   assert (s != NULL);

   // N.B. tcp_add_segment_aux will copy the data into a list node - free the original.
   st->seg_list = tcp_add_segment_aux (st->seg_list, st->seg_list, s);
   XFREE(s);
}


// --- tcp_add_stream ----------------------------------------------------------
tcp_stream_t *
tcp_add_stream (
   in6addr_t *src_ip,
   in6addr_t *dst_ip,
   uint16_t src_port,
   uint16_t dst_port
) {
   assert (src_ip != NULL);
   assert (dst_ip != NULL);
   tcp_stream_t *st;
   list_data_t st_data;

   st = tcp_make_stream (src_ip, dst_ip, src_port, dst_port);
   assert (st != NULL);

   st_data.data = st;
   st_data.size = sizeof (tcp_stream_t);
   st_data.de_fn = tcp_stream_destructor;
   st_data.eq_fn = tcp_stream_eq;

   // N.B. list_prepend will copy the data into a list node - free the original.
   tcp_stream = list_prepend (&st_data, tcp_stream);
   XFREE(st);
//   fprintf (stderr, "<+ %p +>\\n", (void *) list_head (tcp_stream)); 
   return (tcp_stream_t *) list_head (tcp_stream);
}
