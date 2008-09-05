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

#include "list.h"

/** Create a new list node.
 */
static list_t
list_new_node (list_data_t *d);

// --- list_new_node -----------------------------------------------------------
// N.B. the data is copied into the list node. We should then deallocate the
// copied data (without following any pointers it may contain in order to leave
// anything it points to intact).
list_t
list_new_node (list_data_t *d) {
   assert (d != NULL);
   assert (d->size >= 0);
   assert (d->de_fn != NULL);
   assert (d->eq_fn != NULL);

   list_t n;
   void *doff;

   n = (list_t) calloc (1, d->size + sizeof (list_node_t));
   assert (n != NULL);
   // data offset within a list_node_t (i.e. after the pointers)
   doff = (void *)(n + 1);
   
   memcpy (doff, d->data, d->size);
	n->destructor = d->de_fn;
   n->eq = d->eq_fn;
   return n;
}


// --- list_is_empty -----------------------------------------------------------
Bool
list_is_empty (list_t lst) {
   return lst == NULL;
}


// --- list_head ---------------------------------------------------------------
// Returns a pointer to the data section of the first node in the list.
void *
list_head (list_t lst) {
   assert (list_is_empty (lst) == FALSE);
   return lst + 1;
}


// --- list_tail ---------------------------------------------------------------
list_t
list_tail (list_t lst) {
   assert (list_is_empty (lst) == FALSE);
   return lst->next;
}


// --- list_get_next -----------------------------------------------------------
list_t
list_get_next (list_t lst) {
   assert (lst != NULL);
   return lst->next;
}


// --- list_get_prev -----------------------------------------------------------
list_t
list_get_prev (list_t lst) {
   assert (lst != NULL);
   return lst->prev;
}


// --- list_set_next -----------------------------------------------------------
void
list_set_next (list_t lst, list_t next) {
   assert (lst != NULL);
   lst->next = next;
}


// --- list_set_prev -----------------------------------------------------------
void
list_set_prev (list_t lst, list_t prev) {
   assert (lst != NULL);
   lst->prev = prev;
}


// --- list_prepend ------------------------------------------------------------
list_t
list_prepend (list_data_t *d, list_t h) {
   list_t n = list_new_node (d);
   assert (n != NULL);
   
   if (list_is_empty (h) != FALSE) {
      n->next = NULL;
      n->prev = NULL;
   }
   else {
      n->next = h;
      n->prev = NULL;
      h->prev = n;
   }
   
	return n;
}

// --- list_delete_head --------------------------------------------------------
list_t
list_delete_head (list_t h) {
   list_t n = list_tail (h);
   h->destructor (h);
   XFREE(h);

   if (list_is_empty (n) == FALSE) {
      n->prev = NULL;
   }
   return n;
}

// --- list_delete -------------------------------------------------------------
// Delete a complete list.
void
list_delete (list_t h) {
   if (list_is_empty (h)) {
      return;
   }
   else {
      list_delete (list_delete_head (h));
   }
}

// --- list_find ---------------------------------------------------------------
// N.B. This could be expressed better by using a single return and nested "?:" 
// expressions but the syntax make that almost unreadable.
list_t
list_find (void *s, list_t h) {
   if (list_is_empty (h)) {
      return NULL;
   } 
   else if (h->eq (list_head (h), s) != FALSE) {
      return h;
   }
   else {
      return list_find (s, list_tail (h));
   }
}

// --- list_replace ------------------------------------------------------------
void
list_replace (list_t old, list_t new) {
   if (old->prev != NULL) {
      old->prev->next = new;
   }
   new->next = old->next;
   new->prev = old->prev;
   old->prev = NULL;
   old->next = NULL;
}
