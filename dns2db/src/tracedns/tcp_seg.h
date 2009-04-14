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

#ifndef TCP_SEG_H
#define TCP_SEG_H

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <netinet/in.h>
#include "global.h"
#include "list.h" 

// TCP segment data
typedef struct segment {
   uint32_t seq_no;
   size_t datasize;
   uint8_t *data;
} seg_t, *seg_list_t;


/** Make a new segment.
 */
seg_t *
tcp_seg_make_seg (
   uint32_t seq_no, //!< TCP sequence number
   uint8_t *data, //!< In: array of TCP segment data.
   uint32_t bytes //!< Number of bytes of data.
);


/** Deallocate all memory used for a segment, including its data.
 */
void
tcp_seg_free (
   seg_t *s //!< In: Segment to free.
);

/** Get segment sequence number.
 */
unsigned int
tcp_seg_get_seq_no (
   seg_t *s //!< In: segment pointer.
);

/** Get segment data.
 */
uint8_t *
tcp_seg_get_data (
   seg_t *s //!< In: segment pointer.
);

/** Get segment data size.
 */
size_t
tcp_seg_get_datasize (
   seg_t *s //!< In: segment pointer.
);

/** Are the sequence numbers of the segments equal.
 */
Bool
tcp_seg_eq_seq_no (
   seg_t *s1, //!< In: segment pointer.
   seg_t *s2 //!< In: segment pointer.
);

/** Destroy a segment list node. Deallocates all memory used for a segment list
 * node.
 */
void
tcp_seg_destructor (
   void *n //!< In: segment list node.
);

/** Are the segments equal. Segments are considered equal if their sequence
 * numbers are equal.
 */
Bool
tcp_seg_eq (
   void *s1, //!< In: segment pointer.
   void *s2 //!< In: segment pointer.
);

#endif

