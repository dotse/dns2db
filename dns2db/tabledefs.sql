--
-- Copyright (c) 2007 .SE (The Internet Infrastructure Foundation).
--                  All rights reserved.
--
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions
-- are met:
-- 1. Redistributions of source code must retain the above copyright
--    notice, this list of conditions and the following disclaimer.
-- 2. Redistributions in binary form must reproduce the above copyright
--    notice, this list of conditions and the following disclaimer in the
--    documentation and/or other materials provided with the distribution.
-- 
-- THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
-- IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-- WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-- ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
-- DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
-- DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
-- GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
-- INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
-- IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
-- OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
-- IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-- ##################################################################### 
--------------------------------------------------------------------------------
-- DNS2DB template database.
--
-- The database is designed to mainly store detailed information about 
-- DNS messages, where they came from and when. 
--
-- The database is intened to be used in a live capture scenario potentially
-- receiving tens of thousands DNS messages per second. Overall write 
-- performance has been prioritized at the cost of concurrency and accuracy (few
-- or no constraints).
--
-- N.B. The default DBMS used is SQLite3. Design and SQL-syntax adjusted 
-- accordingly.
--------------------------------------------------------------------------------
pragma page_size = 4096;
pragma default_cache_size = 1000;

create table trace (
   id integer primary key autoincrement,
   s integer,
   us integer,
   ether_type integer,
   protocol integer,
   src_addr integer,
   dst_addr integer,
   src_port integer --,
   -- check (ether_type between 0 and 65535),
   -- check (protocol between 0 and 65535),
   -- check (src_port between 0 and 65535)
   -- foreign key (ether_type) references ether_type
   -- foreign key (src_addr) references addr
   -- foreign key (dst_addr) references addr
);


create table unhandled_packet (
   trace_id integer primary key,
   packet blob,
   reason text
   -- foreign key (trace_id) references trace
);


create table addr (
   id integer primary key autoincrement,
   addr text,
   unique (addr) -- on conflict replace
);


create table dns_header (
   trace_id integer, 
   msg_id integer, 
   qr integer,
   aa integer,
   tc integer,
   rd integer,
   cd integer,
   ra integer,
   ad integer,
   opcode integer,
   rcode integer,
   edns0 integer,
   do integer,
   extended_rcode integer,
   version integer,
   z integer,
   qd_count integer,
   an_count integer,
   ns_count integer,
   ar_count integer,
   primary key (trace_id, msg_id) --,
   -- check (msg_id between 0 and 65535),
   -- check (qd_count between 0 and 255),
   -- check (an_count between 0 and 255),
   -- check (ns_count between 0 and 255),
   -- check (ar_count between 0 and 255)
   -- foreign key (trace_id) references trace
   -- foreign key (msg_id) references dns_header
);

create table dns_rr (
   trace_id integer,
   msg_id integer,
   n integer, -- count to distinguish records of the same kind
   rr_tag text, -- QD, NS, AR, AN
   --rr_name text,
   rr_lvl1dom text, -- (cc)TLD, 1st level domain
   rr_lvl2dom text, -- subdomain, 2nd level domain
   rr_restdom text, -- rest of domains
   rr_type integer,
   rr_class integer,
   rr_ttl integer,
   primary key (trace_id, msg_id, n, rr_tag)--,
   --check (rr_tag in ('QD','NS','AR','AN')) 
   -- foreign key (trace_id) references trace
   -- foreign key (msg_id) references dns_header
   -- foreign key (rr_type) references dns_type
   -- foreign key (rr_class) references dns_class
);

create table dns_rr_data (
   trace_id integer,
   msg_id integer,
   rr_n integer,
   rr_tag text,
   rdf_n integer,
   rdf_type integer,
   rdf_data text,
   primary key (trace_id, msg_id, rr_n, rr_tag, rdf_n)
);
----------------------------
--- Lookup tables and views.
----------------------------
create view q
as
   select t.id as id,
      t.s as ts,
      d.msg_id as msg_id,
      0 as Client_num,
      a.addr as Client,
      t.src_port as src_port,
      rr_type as Qtype,
      rr_class as Qclass,
      msglen,
      rtrim (restdom || lvl2dom || lvl1dom, '.') as Qname,
      Opcode,
      Rd,
      Opt_RR,
      rtrim (lvl2dom || lvl1dom, '.') as E1
   from trace t
   join addr a on (t.src_addr = a.id)
   join (
      select dh.trace_id trace_id,
         dh.msg_id msg_id,
         rr_type,
         rr_class,
         0 msglen,
         case rr_restdom when null then '' else rr_restdom end restdom,
         case rr_lvl2dom when null then '' else rr_lvl2dom end lvl2dom,
         case rr_lvl1dom when null then '' else rr_lvl1dom end lvl1dom,
         opcode,
         rd,
         rr_type = 41 Opt_RR
      from dns_header dh
      join dns_rr dr on (dh.trace_id = dr.trace_id and dh.msg_id = dr.msg_id)
   ) d on (d.trace_id = t.id);

--   Do INTEGER, 
--   Version TEXT, 
--   E1 TEXT, 
--   E2 TEXT


create table dns_rr_type (
   id integer primary key,
   type text,
   description text
);

create table dns_q_type (
   id integer primary key,
   type text,
   description text
);

create view dns_type_all
as
   select id, type, description from dns_rr_type
   union
   select id, type, description from dns_q_type;

create table ether_type (
   id integer primary key,
   type text, 
   description text
);


create table dns_class (
   id integer primary key,
   class text,
   description text
);

create table dns_q_class (
   id integer primary key,
   class text,
   description text
);

create view dns_class_all 
as
   select id, class, description from dns_class
   union
   select id, class, description from dns_q_class;

-- Protocols defined by www.iana.org (nb. these assignments may change).
create table protocol (
   id integer primary key,
   protocol text,
   description text
);

----------------------
--- Lookup table data.
----------------------
insert into dns_rr_type values (1, 'A', 'Host address.');
insert into dns_rr_type values (2, 'NS', 'Authoritative name server.');
insert into dns_rr_type values (3, 'MD', 'Mail destination (Obsolete).');
insert into dns_rr_type values (4, 'MF', 'Mail forwarder (Obsolete).');
insert into dns_rr_type values (5, 'CNAME', 'Canonical name for an alias.');
insert into dns_rr_type values (6, 'SOA', 'Start of zone of authority.');
insert into dns_rr_type values (7, 'MB', 'Mailbox domain name.');
insert into dns_rr_type values (8, 'MG', 'Mail group member.');
insert into dns_rr_type values (9, 'MR', 'Mail rename domain name.');
insert into dns_rr_type values (10, 'NULL', 'Null RR.');
insert into dns_rr_type values (11, 'WKS', 'Well known service description.');
insert into dns_rr_type values (12, 'PTR', 'Domain name pointer.');
insert into dns_rr_type values (13, 'HINFO', 'Host information.');
insert into dns_rr_type values (14, 'MINFO', 'Mailbox or mail list information.');
insert into dns_rr_type values (15, 'MX', 'Mail exchange.');
insert into dns_rr_type values (16, 'TXT', 'Text strings.');
insert into dns_rr_type values (17, 'RP', 'RFC 1183.');
insert into dns_rr_type values (18, 'AFSDB', 'RFC 1183.');
insert into dns_rr_type values (19, 'X25', 'RFC 1183.');
insert into dns_rr_type values (20, 'ISDN', 'RFC 1183.');
insert into dns_rr_type values (21, 'RT', 'RFC 1183.');
insert into dns_rr_type values (22, 'NSAP', 'RFC 1706.');
insert into dns_rr_type values (23, 'NSAP_PTR', 'RFC 1348.');
insert into dns_rr_type values (24, 'SIG', '2535typecode.');
insert into dns_rr_type values (25, 'KEY', '2535typecode.');
insert into dns_rr_type values (26, 'PX', 'RFC 2163.');
insert into dns_rr_type values (27, 'GPOS', 'RFC 1712.');
insert into dns_rr_type values (28, 'AAAA', 'IPV6 address.');
insert into dns_rr_type values (29, 'LOC', 'LOC record, RFC 1876.');
insert into dns_rr_type values (30, 'NXT', '2535typecode.');
insert into dns_rr_type values (31, 'EID', 'draft-ietf-nimrod-dns-01.txt.');
insert into dns_rr_type values (32, 'NIMLOC', 'draft-ietf-nimrod-dns-01.txt.');
insert into dns_rr_type values (33, 'SRV', 'SRV record, RFC 2782.');
insert into dns_rr_type values (34, 'ATMA', 'http://www.jhsoft.com/rfc/af-saa-0069.000.rtf.');
insert into dns_rr_type values (35, 'NAPTR', 'RFC 2915.');
insert into dns_rr_type values (36, 'KX', 'RFC 2230.');
insert into dns_rr_type values (37, 'CERT', 'RFC 2538.');
insert into dns_rr_type values (38, 'A6', 'RFC 2874.');
insert into dns_rr_type values (39, 'DNAME', 'RFC 2672.');
insert into dns_rr_type values (40, 'SINK', 'dnsind-kitchen-sink-02.txt.');
insert into dns_rr_type values (41, 'OPT', 'Pseudo OPT record.');
insert into dns_rr_type values (42, 'APL', 'RFC 3123.');
insert into dns_rr_type values (43, 'DS', 'draft-ietf-dnsext-delegation.');
insert into dns_rr_type values (44, 'SSHFP', 'SSH Key Fingerprint.');
insert into dns_rr_type values (45, 'IPSECKEY', 'draft-richardson-ipseckey-rr-11.txt.');
insert into dns_rr_type values (46, 'RRSIG', 'draft-ietf-dnsext-dnssec-25.');
insert into dns_rr_type values (47, 'NSEC', '');      
insert into dns_rr_type values (48, 'DNSKEY', '');

insert into dns_q_type values (252, 'AXFR', 'Request for a transfer of an entire zone.');
insert into dns_q_type values (253, 'MAILB', 'Request for mailbox-related records (MB, MG, or MR).');
insert into dns_q_type values (254, 'MAILA', 'Request for mail agent RRs (Obsolete - see MX).');
insert into dns_q_type values (255, '*', 'A request for all records.');

insert into dns_class values (1, 'IN', 'The Internet.');
insert into dns_class values (2, 'CS', 'The CSNET (Obsolete).');
insert into dns_class values (3, 'CH', 'The CHAOS class.');
insert into dns_class values (4, 'HS', 'Hesiod (Project Athena Technical Plan, April 1987).');

insert into dns_q_class values (255, '*', 'Any class.');

insert into ether_type values (512, 'ETHERTYPE_PUP', 'PUP protocol.');
insert into ether_type values (2048, 'ETHERTYPE_IP', 'IP protocol.');
insert into ether_type values (2054, 'ETHERTYPE_ARP', 'Address resolution protocol.');
insert into ether_type values (32821, 'ETHERTYPE_REVARP', 'Reverse address resolution protocol.');
insert into ether_type values (33024, 'ETHERTYPE_VLAN', 'IEEE 802.1Q VLAN tagging.');
insert into ether_type values (34524, 'ETHERTYPE_IPV6', 'IPv6 protocol.');
insert into ether_type values (36864, 'ETHERTYPE_LOOPBACK', 'Used to test interfaces.');

insert into protocol values (0, 'IPPROTO_IP', 'Dummy for IP or IP6 hop-by-hop options.');
insert into protocol values (1, 'IPPROTO_ICMP', 'Control Message Protocol.');
insert into protocol values (6, 'IPPROTO_TCP', 'Transmission Control Protocol');
insert into protocol values (17, 'IPPROTO_UDP', 'User Datagram Protocol.');
