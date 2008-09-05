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
 */

#ifndef GLOBAL_H
#define GLOBAL_H

#include "../../config.h"
#if defined(HAVE_NET_ETHERNET_H)
   #include <net/ethernet.h>
#elif defined(HAVE_NET_ETHERTYPES_H)
   #include <net/ethertypes.h>
#else
   #error "Can not find ethernet/ethertypes header, ethernet.h/ethertypes.h"
#endif

#if defined(HAVE_LIBTRACE_H)
   #include <libtrace.h>
#else
   #error "Can not find libtrace header, libtrace.h"
#endif

#ifndef TRACEDNS_VERSION
#define TRACEDNS_VERSION "TRACEDNS 2.0"
#endif

// Hack for Linux which does not include this in ethernet.h/ethertypes.h
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

// A "safer" free (see CERT C Secure Coding Standard, 
// https://www.securecoding.cert.org)
#define XFREE(a) do {free ((a)); (a) = NULL;} while (0)

typedef enum Exit_status {FAILURE, SUCCESS} Exit_status;
typedef enum Bool {FALSE, TRUE} Bool;

#endif

