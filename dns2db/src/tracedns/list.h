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

/*
 *  A simple doubly linked list implementation for tracedns loosely based on an
 *  example by Thomas Burger: 
 *    http://www.ibm.com/developerworks/linux/library/l-tip-generic.html)
 *
 */

#ifndef LIST_H
#define LIST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "global.h"

typedef struct list_node_t *list_t;
typedef void (*list_node_destructor_fn) (void *);
typedef Bool (*list_node_eq_fn) (void *, void *);

typedef struct list_node_t {
   list_node_destructor_fn destructor;
   list_node_eq_fn eq;
   list_t next;
   list_t prev;
} list_node_t;

typedef struct list_data_t {
   void *data;
   size_t size;
   list_node_destructor_fn de_fn;
   list_node_eq_fn eq_fn;
} list_data_t;


/** Is the list empty?
 */
Bool
list_is_empty (
   list_t lst //!< In: pointer to list.
);

/** Head of list. Returns the actual data in the first node of the list.
 */
void *
list_head (
   list_t lst //!< In: pointer to list.
);

/** Tail of list.
 */
list_t
list_tail (
   list_t lst //!< In: pointer to list.
);

/** Next node in the list or NULL otherwise.
 */
list_t
list_get_next (
   list_t lst //!< In: pointer to list.
);

/** Previous node in the list or NULL otherwise.
 */
list_t
list_get_prev (
   list_t lst //!< In: pointer to list.
);

/** Set the next node in the list to next.
 */
void
list_set_next (
   list_t lst, //!< In: pointer to list.
   list_t next //!< In: pointer to new list (node).
);

/** Set the previous node in the list prev.
 */
void
list_set_prev (
   list_t lst, //!< In: pointer to list.
   list_t prev //!< In: pointer to previous list node.
);


/** Prepend an element to a list.
 */
list_t
list_prepend (
   list_data_t *d, //!< In: list data.
   list_t h //!< In: pointer to list.
);

/** Delete a single node in a list.
 */
list_t
list_delete_head (
   list_t h //!< In: pointer to list.
);

/** Delete a complete list.
 */
void
list_delete (
   list_t h //!< In: pointer to list.
);

/** Find a node in a list. Returns pointer to the node if found and NULL 
 * otherwise.
 */
list_t
list_find (
   void *d, //!< In: list data to find.
   list_t h //!< In: pointer to list.
);

/** Destructively replace n1 with n2.
 */
void
list_replace (
   list_t n1, //!< In: pointer to old list node.
   list_t n2 //!< In: pointer to new list node.
);

#endif

