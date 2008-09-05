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
#include "line_parser.h"

// === Local function prototypes ============================================

char *
read_addr (FILE *fp);

unsigned long
read_long_aux (FILE *fp, unsigned long b);

long
read_long (FILE *fp);

unsigned char
read_hex_char (FILE *fp);

unsigned char *
read_data (FILE *fp, unsigned int len);


// === Function implementations ================================================

// --- read_long_aux -----------------------------------------------------------
unsigned long
read_long_aux (FILE *fp, unsigned long b) {
   int c = fgetc (fp);
   return isdigit (c) ? read_long_aux (fp, 10 * b + c - '0') : b;
}


// --- read_long ---------------------------------------------------------------
long
read_long (FILE *fp) {
   return read_long_aux (fp, 0);
}


// --- read_addr ---------------------------------------------------------------
char *
read_addr (FILE *fp) {
   int c;
   int n = INET6_ADDRSTRLEN; // guard against buffer overflow
   char *buf = (char *) calloc (1, INET6_ADDRSTRLEN + 1);
   assert (buf != NULL);
   char *pos = buf;
   
   while ((c = fgetc (fp)) != EOF) {
      if ((isxdigit (c) || c == ':' || c == '.') && n-- > 0) {
         *pos++ = c;
      }
      else {
         *pos = EOS;
         break;
      }
   }
   return buf;
}


// --- read_hex_char -----------------------------------------------------------
unsigned char
read_hex_char (FILE *fp) {
   int c, i;
   unsigned char y = 0;
   unsigned char x = 0;
   
   for (i = 0, c = fgetc (fp); isxdigit (c) && i < 2; i++, c = fgetc (fp)) {
      x = isdigit (c) ? c - '0' : toupper (c) - 'A' + 10;
      y |= i == 0 ? x << 4 : x;
   }
   ungetc (c, fp);
   return y;
}


// --- read_data ---------------------------------------------------------------
unsigned char *
read_data (FILE *fp, unsigned int len) {
   int c;
   unsigned char *data;
   data = (unsigned char *) calloc (1, len);
   assert (data != NULL);
   unsigned char *p = data;
   
   while (len > 0) {
      *p++ = read_hex_char (fp);
      len--;
   }
   c = fgetc (fp); // eat newline
   return data;
}


// --- parse_file --------------------------------------------------------------
trace_t *
parse_line (FILE *fp) {
   State s = SECS;
   trace_t *t = make_trace ();
   
   while (feof (fp) == FALSE) {

      switch (s) {
         case SECS: trace_set_seconds (t, read_long (fp)); s++; break;
         case USECS: trace_set_micro_seconds (t, read_long (fp)); s++; break;
         case ETHERTYPE: trace_set_ethertype (t, read_long (fp)); s++; break;
         case SRC: trace_set_src_addr (t, read_addr (fp)); s++; break;
         case DST: trace_set_dst_addr (t, read_addr (fp)); s++; break;
         case PORT: trace_set_port (t, read_long (fp)); s++; break;
         case PROTO: trace_set_protocol (t, read_long (fp)); s++; break;
         case LEN: trace_set_length (t, read_long (fp)); s++; break;
         case DATA: 
            trace_set_data (t, read_data (fp, trace_get_length (t))); 
            s++; 
            break;
         case DONE: return t;
         default:
            s = ERR;
            trace_free (t);
            return NULL;
      }
   }
   return NULL;
}
