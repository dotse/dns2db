#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <assert.h>
#include <ctype.h>
#include <arpa/nameser.h>
#include <syslog.h>

//#include "string_counter.h"
#include "read_pcap.h"

#define DNS_MSG_HDR_SZ 12
#define RFC1035_MAXLABELSZ 63

static int
rfc1035NameUnpack(const char *buf, size_t sz, off_t * off, char *name, int ns)
{
    off_t no = 0;
    unsigned char c;
    size_t len;
    static int loop_detect = 0;
    if (loop_detect > 2)
	return 4;		/* compression loop */
    if (ns <= 0)
	return 4;		/* probably compression loop */
    do {
	if ((*off) >= sz)
	    break;
	c = *(buf + (*off));
	if (c > 191) {
	    /* blasted compression */
	    int rc;
	    unsigned short s;
	    off_t ptr;
	    memcpy(&s, buf + (*off), sizeof(s));
	    s = ntohs(s);
	    (*off) += sizeof(s);
	    /* Sanity check */
	    if ((*off) >= sz)
		return 1;	/* message too short */
	    ptr = s & 0x3FFF;
	    /* Make sure the pointer is inside this message */
	    if (ptr >= sz)
		return 2;	/* bad compression ptr */
	    if (ptr < DNS_MSG_HDR_SZ)
		return 2;	/* bad compression ptr */
	    loop_detect++;
	    rc = rfc1035NameUnpack(buf, sz, &ptr, name + no, ns - no);
	    loop_detect--;
	    return rc;
	} else if (c > RFC1035_MAXLABELSZ) {
	    /*
	     * "(The 10 and 01 combinations are reserved for future use.)"
	     */
	    break;
	    return 3;		/* reserved label/compression flags */
	} else {
	    (*off)++;
	    len = (size_t) c;
	    if (len == 0)
		break;
	    if (len > (ns - 1))
		len = ns - 1;
	    if ((*off) + len > sz)
		return 4;	/* message is too short */
	    memcpy(name + no, buf + (*off), len);
	    (*off) += len;
	    no += len;
	    *(name + (no++)) = '.';
	}
    } while (c > 0);
    if (no > 0)
	*(name + no - 1) = '\0';
    /* make sure we didn't allow someone to overflow the name buffer */
    assert(no <= ns);
    return 0;
}

static off_t
grok_question(const char *buf, int len, off_t offset, char *qname, unsigned short *qtype, unsigned short *qclass)
{
    unsigned short us;
    char *t;
    int x;
    x = rfc1035NameUnpack(buf, len, &offset, qname, MAX_QNAME_SZ);
    if (0 != x)
	return 0;
    if ('\0' == *qname)
	strcpy(qname, ".");
    /* XXX remove special characters from QNAME */
    while ((t = strchr(qname, '\n')))
	*t = ' ';
    while ((t = strchr(qname, '\r')))
	*t = ' ';
    for (t = qname; *t; t++)
	*t = tolower(*t);
    if (offset + 4 > len)
	return 0;
    memcpy(&us, buf + offset, 2);
    *qtype = ntohs(us);
    memcpy(&us, buf + offset + 2, 2);
    *qclass = ntohs(us);
    offset += 4;
    return offset;
}

static off_t
grok_additional_for_opt_rr(const char *buf, int len, off_t offset, dns_message * m)
{
    int x;
    unsigned short sometype;
    unsigned short someclass;
    unsigned short us;
    char somename[MAX_QNAME_SZ];
    x = rfc1035NameUnpack(buf, len, &offset, somename, MAX_QNAME_SZ);
    if (0 != x)
	return 0;
    if (offset + 10 > len)
	return 0;
    memcpy(&us, buf + offset, 2);
    sometype = ntohs(us);
    memcpy(&us, buf + offset + 2, 2);
    someclass = ntohs(us);
    if (sometype == T_OPT) {
	m->edns.found = 1;
	memcpy(&m->edns.version, buf + offset + 5, 1);
	memcpy(&us, buf + offset + 6, 2);
	us = ntohs(us);
	m->edns.DO = (us >> 15) & 0x01;		/* RFC 3225 */
    }
    /* get rdlength */
    memcpy(&us, buf + offset + 8, 2);
    us = ntohs(us);
    offset += 10;
    if (offset + us > len)
	return 0;
    offset += us;
    return offset;
}

static unsigned short get_msg_id(const char *buf)
{
 
  int msgId_b1 =0;
  int msgId_b2 =0;
  memcpy(&msgId_b1,buf,1);
  msgId_b1 = msgId_b1 << 8; 
  memcpy(&msgId_b2,buf+1,1);
  return (msgId_b1 | msgId_b2);
}



dns_message *
handle_dns(const char *buf, int len)
{
    unsigned short us;
    off_t offset;
    int qdcount;
    int ancount;
    int nscount;
    int arcount;
    dns_message *m = calloc(1, sizeof(*m));
    assert(m);
    m->msglen = (unsigned short) len;

    if (len < DNS_MSG_HDR_SZ) {
	m->malformed = 1;
	return m;
    }
    

    
    
    //test = 0x0f & test;
    m->msg_id = get_msg_id(buf);

    memcpy(&us, buf + 2, 2);
    us = ntohs(us);
    m->qr = (us >> 15) & 0x01;

#if 0
    aa = (us >> 10) & 0x01;
    tc = (us >> 9) & 0x01;
    ra = (us >> 7) & 0x01;
#endif
    m->opcode = (us >> 11) & 0x0F;
    m->rd = (us >> 8) & 0x01;
    m->rcode = us & 0x0F;

    memcpy(&us, buf + 4, 2);
    qdcount = ntohs(us);
    memcpy(&us, buf + 6, 2);
    ancount = ntohs(us);
    memcpy(&us, buf + 8, 2);
    nscount = ntohs(us);
    memcpy(&us, buf + 10, 2);
    arcount = ntohs(us);

    offset = DNS_MSG_HDR_SZ;

    /*
     * Grab the first question
     */
    if (qdcount > 0 && offset < len) {
	off_t new_offset;
	new_offset = grok_question(buf, len, offset, m->qname, &m->qtype, &m->qclass);
	if (0 == new_offset) {
	    m->malformed = 1;
	    return m;
	}
	offset = new_offset;
	qdcount--;
    }
    assert(offset <= len);
    /*
     * Gobble up subsequent questions, if any
     */
    while (qdcount > 0 && offset < len) {
	off_t new_offset;
	char t_qname[MAX_QNAME_SZ];
	unsigned short t_qtype;
	unsigned short t_qclass;
	new_offset = grok_question(buf, len, offset, t_qname, &t_qtype, &t_qclass);
	if (0 == new_offset) {
	    /*
	     * point offset to the end of the buffer to avoid any subsequent processing
	     */
	    offset = len;
	    break;
	}
	offset = new_offset;
	qdcount--;
    }
    assert(offset <= len);

    if (arcount > 0 && offset < len) {
	off_t new_offset;
	new_offset = grok_additional_for_opt_rr(buf, len, offset, m);
	if (0 == new_offset) {
	    offset = len;
	} else {
	    offset = new_offset;
	}
	arcount--;
    }
    assert(offset <= len);
    return m;
}



  
