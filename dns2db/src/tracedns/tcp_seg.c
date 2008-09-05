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
#include "tcp_seg.h"

// --- tcp_seg_make_seg --------------------------------------------------------
seg_t *
tcp_seg_make_seg (uint32_t seq_no, uint8_t *data, uint32_t bytes) {
   seg_t *s = (seg_t *) calloc (1, sizeof (seg_t));
   assert (s != NULL);

   s->seq_no = seq_no;
   s->datasize = bytes;

   s->data = bytes > 0 ? (uint8_t *) calloc (1, bytes) : NULL;
   assert ((bytes > 0 && s->data != NULL) || (bytes == 0 && s->data == NULL));
   memcpy (s->data, data, bytes);

   return s;
}

// --- tcp_seg_free ------------------------------------------------------------
void
tcp_seg_free (seg_t *s) {
   XFREE(s->data);
   XFREE(s);
}

// --- tcp_seg_get_data --------------------------------------------------------
uint8_t *
tcp_seg_get_data (seg_t *s) {
   return s->data;
}

// --- tcp_seg_get_datasize ----------------------------------------------------
size_t
tcp_seg_get_datasize (seg_t *s) {
   return s->datasize;
}

// --- tcp_seg_get_seq_no ------------------------------------------------------
unsigned int
tcp_seg_get_seq_no (seg_t *s) {
   return s->seq_no;
}

// --- tcp_seg_eq_seq_no -------------------------------------------------------
Bool
tcp_seg_eq_seq_no (seg_t *s1, seg_t *s2) {
   return s1->seq_no == s2->seq_no;
}

// --- tcp_seg_destructor ------------------------------------------------------
// N.B.: the destructor should only deallocate dynamically allocated resources
// in the segment - not the segment itself. The "segment" is a byte-for-byte 
// copy of the real segment and is technicaly a part of the list node. The
// "segment" itself will be deallocated when the list node is deallocated.
void
tcp_seg_destructor (void *n) {
   seg_t *s = (seg_t *) list_head ((list_t) n);
   assert (s != NULL);
   XFREE(s->data);
}

// --- tcp_seg_eq --------------------------------------------------------------
Bool
tcp_seg_eq (void *s1, void *s2) {
   assert (s1 != NULL || s2 != NULL);
   return ((seg_t *) s1)->seq_no == ((seg_t *) s2)->seq_no;
}
