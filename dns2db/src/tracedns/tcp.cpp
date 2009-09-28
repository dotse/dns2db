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
 
extern "C" {
   #include "tcp.h"
}

#include <map>
#include <list>

/// TCP Stream id class - serves as the key in the streams map
class Stream_id
{
   public:
      /// constructor
      Stream_id()
      {
      }
      /// constructor taking source and destination adresses
      Stream_id(  in6addr_t &src_ip, 
                  in6addr_t &dst_ip, 
                  uint16_t src_port,
                  uint16_t dst_port)
      {
         m_src_ip    = src_ip;
         m_dst_ip    = dst_ip;
         m_src_port  = src_port;
         m_dst_port  = dst_port;
      }
   
      /// < comparison operator for the std::map 
      bool operator < (const Stream_id &rhs) const 
      {
         return memcmp(this,&rhs,sizeof(Stream_id)) < 0; 
      } 
   private:
      in6addr_t m_src_ip,  m_dst_ip;
      uint16_t  m_src_port,m_dst_port;
};

/// TCP data segment container 
/** Data_segment contains the data found in a single tcp packet
 * Data_segment are inerted into a list in the Stream class
 */
class Data_segment
{
   public:
      /// Constructor taking a memory block with packet content
      Data_segment( uint8_t *data, size_t len)
      {
         m_datasize = len;
         m_data = new uint8_t[len];
         for (int i=0; i<len; i++)
         {
            m_data[i]=data[i];
         }
      }
      /// Copy constructor
      Data_segment(const Data_segment &other)
      {
         m_datasize = other.m_datasize;
         m_data = new uint8_t[m_datasize];
         for (int i=0; i<m_datasize; i++)
         {
            m_data[i]=other.m_data[i];
         }      
      }
      /// Destructor
      ~Data_segment()
      {
         delete []m_data;
      }
      
      /// size of the data
      size_t    m_datasize;
      /// pointer to the data
      uint8_t  *m_data;
};

int g_count = 0;

/// TCP Stream class
/** The Stream class has an Stream_id and a list of Data_segemnts that make up 
 *  a tcp data stream.
 *  The Streams are organized into a global map ( g_tcp_streams ) indexed by a Stream_id
 */
class Stream
{
   public:
      /// Constructor
      Stream()
      {
         m_ser       = g_count++;
         m_content   = false;
         m_nseq      = false;
      }
      /// add a datasegment to the stream
      /** If the segment has the expected sequence number 
       *  the segment will be added to the list
       */
      void add(   uint32_t seq     /// Sequence number of the segment
                  ,Data_segment &s  /** Data segment */ )
      {
         m_content=true;

         if (m_seq==seq)
         {
          m_content = true;
            if ( (s.m_datasize > 0 && s.m_datasize <= 65535) )
            {
               m_segments.push_back(s);
               m_seq=seq+s.m_datasize;
            }
         }
         if (!m_segments.size())
            m_seq=seq;
      }
      /// checka if there's any content in the stream 
      bool has_content()
      {
         return m_content;
      }
      /// Erase (and free) all segments and reset state
      void erase()
      {
         m_content = false;
         m_nseq    = false;
         m_segments.clear();
         
      }
      /// return the streams data size 
      int get_size()
      {
         int size = 0;
         for (std::list<Data_segment>::iterator it = m_segments.begin();
              it != m_segments.end(); it ++)
         {
            size += it->m_datasize;
         }
         return size;
      }
      /// debug functionality to dump a streams content
      void dump()
      {
         int start=2;
         for (std::list<Data_segment>::iterator it = m_segments.begin();
              it != m_segments.end(); it ++)
         {
            for (int i=start; i< it->m_datasize; i++)
            {
               printf("%02x",it->m_data[i]);
            }
            start = 0;
         }         
         printf("\n");
      }
      /// returns the data in the stream 
      /** The returned data is located in a static buffer shared by all streams
       *  the data is valid until the next call to get_buffer()
       */
      uint8_t *get_buffer()
      {
         int start=2, p=0;
         for (std::list<Data_segment>::iterator it = m_segments.begin();
              it != m_segments.end(); it ++)
         {
            for (int i=0; i< it->m_datasize; i++)
            {
               m_buffer[p++]=it->m_data[i];
               if (p>=0xffff)
                  return m_buffer;
            }
            start = 0;
         }         
         return m_buffer;
      }
   private:
      uint32_t                m_seq;
      int                     m_ser;
      bool                    m_content;
      bool                    m_nseq;
      std::list<Data_segment> m_segments;
   
      static uint8_t          m_buffer[0x10000];
};
uint8_t Stream::m_buffer[0x10000];

std::map<Stream_id,Stream> g_tcp_streams;
 

extern "C" {

/// assemble_tcp builds datastreams out of tcp packets
/** TCP packets are inserted into streams. When the streams are closed
 *  the contained data is returned as a pointer the data 
 *  it is up to the caller to free() the memory returned.
 */
uint8_t *
assemble_tcp (
   in6addr_t *src_ip, 
   in6addr_t *dst_ip, 
   uint16_t src_port,
   uint16_t dst_port,
   uint32_t *rest,
   uint32_t seq,
   uint8_t *data, 
   size_t len,
   char syn,
   char fin,
   char rst,
   char ack
) {
   seq = ntohl (seq);

   Stream_id id ( *src_ip, *dst_ip, src_port, dst_port );
   Stream   &str = g_tcp_streams[id];
   bool data_avail = false;
   
   if (!str.has_content())
   {
      if (syn == 1) 
      {
         Data_segment seg( data, len);
         str.add( seq, seg);
      }
   }
   else
   {
      if (rst == 1) 
      {
         str.erase();
      }
      else if (syn == 1) 
      {
         str.erase();
         Data_segment seg( data, len);
         str.add( seq, seg);
      }
      else if (fin == 0)
      {
         Data_segment seg( data, len);
         str.add( seq, seg);
      }
   }
 
   data = 0;
   data_avail = (str.has_content() && (fin == 1) && (rst == 0));
   if (data_avail)
   {
      *rest = str.get_size();
      if (*rest > 0xffff)
         *rest = 0xffff;
      data = (uint8_t*)malloc(*rest);
      memcpy(data,str.get_buffer(),*rest);
      str.erase();
      g_tcp_streams.erase(id);
   }
   return data;
}


}
