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
#include "packet_handler.h"







// === Local function prototypes ===============================================
/** Get a segment, i.e. the payload, from a datagram.
 */
void *
get_seg (
   uint16_t ethertype, 
   void *dgram, 
   uint8_t *proto, 
   uint32_t *rest, 
   in6addr_t *src_ip, 
   in6addr_t *dst_ip
);

/** Get the UDP packet from a segment.
 */
uint8_t *
get_udp (libtrace_udp_t *udp, uint32_t *rest);



/** Get the payload from a segment, i.e. the TCP or UDP packet.
 */
uint8_t *
get_seg_payload (
   uint8_t proto,
   void *seg,
   uint32_t *rest, // bytes after IP header remaining in seg, i.e the size of the IP payload.
   in6addr_t *src_ip,
   in6addr_t *dst_ip,
   uint16_t *src_port
);

// === Function implementations ================================================
// --- packet_print ------------------------------------------------------------
void
packet_print (
   uint8_t *p, 
   struct timeval ts, 
   uint16_t ethertype, 
   in6addr_t *src_ip, 
   in6addr_t *dst_ip, 
   uint16_t src_port, 
   uint16_t proto, 
   uint32_t remaining
) {
   char src_buf [INET6_ADDRSTRLEN];
   char dst_buf [INET6_ADDRSTRLEN];
   const char *src_addr = NULL; 
   const char *dst_addr = NULL;

   bzero (src_buf, INET6_ADDRSTRLEN);
   bzero (dst_buf, INET6_ADDRSTRLEN);
   
   src_addr = inet_ntop (AF_INET6, src_ip, src_buf, INET6_ADDRSTRLEN);
   dst_addr = inet_ntop (AF_INET6, dst_ip, dst_buf, INET6_ADDRSTRLEN);

   fprintf (
      stdout, 
      "%ld,%ld,%d,%s,%s,%d,%d,%d,", 
      ts.tv_sec, 
      (long) ts.tv_usec, 
      ethertype, 
      src_addr,
      dst_addr,
      src_port,
      proto,
      remaining
   );

   for (unsigned int i = 0; i < remaining; ++i, ++p) {
      if (proto == IPPROTO_TCP && i < 2) {
         continue;
      }
      fprintf (stdout, "%02x", *p);
   }
   fprintf (stdout, "\n");
   fflush (stdout);
}

// --- get_seg -----------------------------------------------------------------
void *
get_seg (
   uint16_t ethertype, 
   void *dgram, 
   uint8_t *proto, 
   uint32_t *rest, 
   in6addr_t *src_ip, 
   in6addr_t *dst_ip
) {
   void *seg = NULL;
   libtrace_ip_t *ip = NULL;
   libtrace_ip6_t *ip6 = NULL;
   switch (ethertype) {
      case ETHERTYPE_IP:
         ip = (libtrace_ip_t *) dgram;
         seg = trace_get_payload_from_ip (ip, proto, rest);
         bzero (src_ip, sizeof (struct in6_addr));
         bzero (dst_ip, sizeof (struct in6_addr));
         
         memcpy ((uint32_t *)src_ip + 3, &(ip->ip_src), sizeof (struct in_addr));
         memcpy ((uint32_t *)dst_ip + 3, &(ip->ip_dst), sizeof (struct in_addr));
         
         break;
      case ETHERTYPE_IPV6:
         ip6 = (libtrace_ip6_t *) dgram;
         seg = trace_get_payload_from_ip6 (ip6, proto, rest);
         *src_ip = ip6->ip_src;
         *dst_ip = ip6->ip_dst;

         break;
      default:
         return NULL;
   }
   return seg;
}


// --- get_udp -----------------------------------------------------------------
uint8_t *
get_udp (libtrace_udp_t *udp, uint32_t *rest) {
   uint8_t *p = NULL;
   uint8_t *tmp = (uint8_t *) trace_get_payload_from_udp (udp, rest);
   if (tmp != NULL) {
      p = (uint8_t *) calloc (1, *rest);
      assert (p != NULL);
      memcpy (p, tmp, *rest);
   }   
   return p;
}


// --- get_seg_payload ---------------------------------------------------------
uint8_t *
get_seg_payload (
   uint8_t proto,
   void *seg,
   uint32_t *rest, // bytes after IP header remaining in seg, i.e the size of the IP payload.
   in6addr_t *src_ip,
   in6addr_t *dst_ip,
   uint16_t *src_port
) {
   unsigned char *port=0;  
   uint8_t *p = NULL;
   libtrace_udp_t *udp = NULL;
   libtrace_tcp_t *tcp = NULL;
   uint16_t dst_port;
   uint8_t *data = NULL;

   p = NULL;
   switch (proto) {
      case IPPROTO_UDP:
         udp = (libtrace_udp_t *) seg;
         port = (unsigned char *)&udp->source;
         *src_port = ( ((unsigned short)(port[0]))<<8) | port[1];

         p = get_udp (udp, rest);
      break;
      case IPPROTO_TCP:

         tcp       = (libtrace_tcp_t *) seg;
         port = (unsigned char *)&tcp->source;
         *src_port = ( ((unsigned short)(port[0]))<<8) | port[1];
         dst_port  = tcp->dest;

         // data is freed by libtrace
         data      = (uint8_t *) trace_get_payload_from_tcp (tcp, rest); 

         // get the assembled TCP packet and remove the individual segments.
         if (data)
            p = assemble_tcp (src_ip, dst_ip, *src_port, dst_port, rest, tcp->seq, 
                           data, *rest, tcp->syn, tcp->fin, tcp->rst, tcp->ack);
         
         break;
      default:
         // Unhandled protocol. Use the whole transport datagram as payload.
         p = (uint8_t *) calloc (1, *rest);
         assert (p != NULL);
         
         memcpy (p, seg, *rest);
   }
   return p;
}


// --- per_packet --------------------------------------------------------------
// assume Ethernet, IP, and DNS from BPF filtering
void 
per_packet (libtrace_packet_t *packet) {
   uint8_t proto = 0;
   uint16_t ethertype = 0;
   uint32_t rest = 0;
   uint16_t src_port = 0;
   void *dgram = NULL;
   void *seg = NULL;
   uint8_t *p = NULL;
   struct timeval ts;
   in6addr_t src_ip;
   in6addr_t dst_ip;

   ts = trace_get_timeval (packet);
   dgram = trace_get_layer3 (packet, &ethertype, &rest);
   if (dgram == NULL) {
      return;   
   }

   seg = get_seg (ethertype, dgram, &proto, &rest, &src_ip, &dst_ip);
   if (seg == NULL) {
      return;
   }
   
   p = get_seg_payload (proto, seg, &rest, &src_ip, &dst_ip, &src_port);
   if (p == NULL) {
      return;
   }

   packet_print (p, ts, ethertype, &src_ip, &dst_ip, src_port, proto, rest);
   XFREE(p);
}
