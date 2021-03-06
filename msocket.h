/*
 * Copyright (c) 2008
 *      Matt Harris.  All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY Mr. Harris AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Mr. Harris OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef INCLUDED_MSOCKET_H
# define INCLUDED_MSOCKET_H		1

/*
**
** DEFINES
**
*/

# define LMS_VERSION			"0.5"
# define LMS_VERSION_INT		0x000050

# define LMS_LEN_V4ADDR			16
# define LMS_LEN_V6ADDR			24

# define LMS_CONNTIMEOUT		60

# define LMSTYPE_ERROR			0
# define LMSTYPE_LOCALLISTEN		1
# define LMSTYPE_LOCALCLIENT		2
# define LMSTYPE_STREAM4		3
# define LMSTYPE_DGRAM4			4
# define LMSTYPE_LISTEN4		5
# define LMSTYPE_STREAM6		6
# define LMSTYPE_DGRAM6			7
# define LMSTYPE_LISTEN6		8

# define LMSFLG_CONNECTED		0x0000001	/* Socket is connected */
# define LMSFLG_LISTEN			0x0000002	/* Socket is listening */
# define LMSFLG_READY			0x0000004	/* Datagram socket is ready */
# define LMSFLG_WAITDNS			0x0000008	/* Waiting for a DNS response */
# define LMSFLG_WAITIDENT		0x0000010	/* Waiting for an ident response */
# define LMSFLG_MUXACTIVE		0x0000020	/* Socket is in the mux */
# define LMSFLG_SSL			0x0000040	/* SSL connection */
# define LMSFLG_SSLHDSHK		0x0000080	/* SSL handshake phase */
# define LMSFLG_SSLRDY			0x0000100	/* SSL is ready */
# define LMSFLG_WAITDESTROY		0x0000200	/* Socket is dead, but we are waiting for DNS and/or ident queries to return before destroying it */
# define LMSFLG_INBOUND			0x0001000	/* Inbound connection via accept() */
# define LMSFLG_OUTBOUND		0x0002000	/* Outbound connection via connect() */
# define LMSFLG_WAITCONN		0x0004000	/* Not yet connected */
# define LMSFLG_PROXIED			0x0008000	/* This socket is via a proxy */
# define LMSFLG_SOCKSNEEDINIT		0x0100000	/* Need to send the Socks5 connect message */
# define LMSFLG_SOCKSNEEDAUTH		0x0200000	/* Need to send the Socks5 connect message */
# define LMSFLG_SOCKSNEEDCONN		0x0400000	/* Need to send the Socks5 connect message */
# define LMSFLG_SOCKSWAITCONN		0x0800000	/* Waiting for the Socks server to establish the connection */
# define LMSFLG_SOCKSWAITINIT		0x1000000	/* Waiting for the socks server to reply to our init */
# define LMSFLG_SOCKSWAITAUTH		0x2000000	/* Waiting for the socks server to reply to our auth */
# define LMSFLG_SOCKSWAITDONE		0x4000000	/* Waiting for the socks server to complete the connection */

# define LMSOPTION_TRANSIENT		0x002		/* Doesn't do anything */
# define LMSOPTION_BLOCK		0x004		/* A blocking socket (default is to set nonblocking mode */
# define LMSOPTION_CWAIT		0x008		/* Blocks during connect() or whatever else, then sets nonblocking mode */
# define LMSOPTION_SSL			0x010		/* Uses SSL - self-explanatory */
# define LMSOPTION_UCREP		0x020		/* For an SSL socket, this sets some additional OpenSSL options for an "unclean" remote end-point which may require bug-adaptability */
# define LMSOPTION_ALLOWIDLE		0x040		/* Allow a socket to idle */
# define LMSOPTION_SOCKS		0x080		/* Use a SOCKS5 proxy */

# define LMSPROXY_NONE			0		/* No proxy */
# define LMSPROXY_SOCKS5		1		/* Socks5 proxy */
# define LMSPROXY_TOR			2		/* Socks5 proxy (Tor) */
# define LMSPROXY_HTTP			3		/* HTTP proxy */

# define LMS_MAXDNSCACHE		30000

# if !defined(LMS_MAXDNSCACHE) || (LMS_MAXDNSCACHE <= 0)
#  define LMS_NODNSCACHE
# endif /* !defined(LMS_MAXDNSCACHE) || (LMS_MAXDNSCACHE <= 0) */
# ifdef LMS_NODNSCACHE
#  define LMS_MAXDNSCACHE		0
# endif /* LMS_NODNSCACHE */

# define LMS_DNS_TYPE_NONE		0
# define LMS_DNS_TYPE_A			1
# define LMS_DNS_TYPE_CNAME		2
# define LMS_DNS_TYPE_PTR		3
# define LMS_DNS_TYPE_TXT		4
# define LMS_DNS_TYPE_MX		5

# define ABSTRACT_NOTHING		0
# define ABSTRACT_STRING		1
# define ABSTRACT_MSOCKET		2
# define ABSTRACT_DNSREQUEST		9
# define ABSTRACT_CALLBACK		10
# define ABSTRACT_MAX			10240

/*
**
** STRUCTURES
**
*/

/*
 * A totally abstract thing, which can be any type of thing stored in the abstract thing...
 * along with a handy variable to tell you what type of thing is pointed to by the
 * pointer stored in the abstract thing.
 */
struct _abstract
{
	unsigned short what;
	void *where;
	/* abstract_callback *how; */
	void (*how)(struct _abstract *);
};
typedef struct _abstract Abstract;

typedef void (*abstract_callback)(struct _abstract *);

/*
 * Declare this up here for use inside of MSocket
 */
struct _MSocket_UDPMsg;

/*
 * MSocket is the structure utilized by our socket abstraction layer
 */
struct _MSocket
{
	uint8_t type;					/* type (MSTYPE_*) */
	uint32_t opts;					/* options for the socket (MSOPTION_*) */

	char *localhost;				/* local address if INET/INET6 or path to file if UNIX */
	int localport;					/* local port if INET/INET6 */
	char *remotehost;				/* remote address if INET/INET6 */
	int remoteport;					/* remote port if INET/INET6 */
	char *remotedns;				/* DNS name of the remote host if INET/INET6 */
	struct in_addr *addr;				/* in_addr structure for evdns and throttling API */

	char *proxyhost;				/* IP address of the proxy which we wish to connect via */
	int proxyport;					/* TCP port for the proxy which we wish to connect via */

	int fd;						/* file descriptor */
	uint64_t flags;					/* flags on the socket/connection/etc (MSFLAG_*) */

	size_t sendQ_sz;				/* allocated size of current sendQ */
	size_t sendQ_len;				/* length of current sendQ */
	unsigned char *sendQ;				/* queue of data to be written */
	time_t last_send;				/* the time at which I last sent data */
	size_t bytes_s;					/* bytes sent via this connection */

	size_t recvQ_sz;				/* allocated size of current recvQ */
	size_t recvQ_len;				/* length of current recvQ */
	unsigned char *recvQ;				/* queue of data to be parsed */
	time_t last_recv;				/* the time at which I last received data */
	size_t bytes_r;					/* bytes received via this connection */

	time_t conn_start;				/* when we started a connect() */
	uint32_t conn_to;				/* time before we should give up on a connect() */

	int (*func_r)(struct _MSocket *);		/* function to call when mux says read */
	int (*func_w)(struct _MSocket *);		/* function to call when mux says write */
	int (*func_e)(struct _MSocket *);		/* function to call when mux cries foul */
	void (*func_p)(struct _MSocket *);		/* function to call when data is available in recvQ */
	void (*func_d)(struct _MSocket_UDPMsg *);	/* function to call when data is available in recvQ from a datagram socket (gets passed a UDP msg structure) */
	void (*func_a)(struct _MSocket *);		/* function to call when a new socket has been accepted on a listener */

	void *appdata;					/* abstract application data */

	/* DNS (temp) crap down here... */
	char *possible_revdns;				/* possible reverse dns, but not yet confirmed */
	uint16_t retries;				/* retry attempts for the reverse DNS lookup */
};
typedef struct _MSocket MSocket;

/*
 * MSocket_UDPMsg
 */
struct _MSocket_UDPMsg
{
	uint8_t type;				/* type (MSTYPE_*) */

	char *localhost;			/* local address if INET/INET6 or path to file if UNIX */
	int localport;				/* local port if INET/INET6 */
	char *remotehost;			/* remote address if INET/INET6 */
	int remoteport;				/* remote port if INET/INET6 */
	char *remotedns;			/* DNS name of the remote host if INET/INET6 */
	struct in_addr *addr;			/* in_addr structure for evdns and throttling API */

	int fd;					/* file descriptor */
	uint64_t flags;				/* flags on the socket/connection/etc (MSFLAG_*) */

	size_t sendQ_sz;			/* allocated size of current sendQ */
	size_t sendQ_len;			/* length of current sendQ */
	unsigned char *sendQ;			/* queue of data to be written */
	time_t last_send;			/* the time at which I last sent data */
	size_t bytes_s;				/* bytes sent via this connection */

	size_t recvQ_sz;			/* allocated size of current recvQ */
	size_t recvQ_len;			/* length of current recvQ */
	unsigned char *recvQ;			/* queue of data to be parsed */
	time_t last_recv;			/* the time at which I last received data */
	size_t bytes_r;				/* bytes received via this connection */

	void (*func_p)(struct _MSocket *);	/* function to call when data is available in recvQ */

	void *appdata;				/* abstract application data, copied from listener */

	/* DNS (temp) crap down here... */
	char *possible_revdns;			/* possible reverse dns, but not yet confirmed */
	uint16_t retries;			/* retry attempts for the reverse DNS lookup */
};
typedef struct _MSocket_UDPMsg MSocket_UDPMsg;

/*
 * Structure for keeping track of throttled IP addresses to prevent brute-force authentication attacks
 */
struct _lms_throttle_data
{
	char ipaddr[16];
	in_addr_t addr;

	time_t last_bad;
	uint32_t offenses;

	struct _lms_throttle_data *prev;
	struct _lms_throttle_data *next;
};
typedef struct _lms_throttle_data lms_throttle_data;

/*
**
** FUNCTIONS
**
*/

/* rand.c */
extern int lms_rand_get(size_t bytes, unsigned char *dst);

/* conn.c */
extern unsigned int lms_throttle_check(in_addr_t ip);
extern int lms_throttle_expire(void);
extern lms_throttle_data *lms_throttle_setbad(MSocket *m);
extern void lms_throttle_remove(lms_throttle_data *throttle);

/* lms.c */
extern int lms_init(unsigned char print);
extern int lms_loop(void);
extern int lms_version_int(void);
extern char *lms_version(void);
extern int lms_proxyset(unsigned short type, char *host, int port);
extern int lms_proxyclear(void);

/* socket.c */
extern void lms_socket_insertfd(MSocket *m);
extern inline MSocket *lms_socket_findbyfd(int fd);
extern void lms_socket_set(MSocket *s, uint32_t options);
extern MSocket *lms_socket_create(uint8_t type);
extern int lms_socket_close(MSocket *ptr);
extern int lms_socket_destroy(MSocket *ptr);
extern unsigned int lms_socket_destroytype(unsigned short type, short killad);
extern unsigned int lms_socket_housekeeping(void);
extern int lms_socket_ilisten(MSocket *s);
extern int lms_socket_iaccept(MSocket *s, MSocket *new);
extern int lms_socket_uaccept(MSocket *s, MSocket *new);
extern int lms_socket_iconn(MSocket *s);
extern int lms_socket_idgram(MSocket *s);
extern int lms_socket_dreply(MSocket_UDPMsg *um, unsigned char *rpl, size_t rpl_len);
extern int lms_socket_appendq(MSocket *m, unsigned char *data, size_t data_len);
extern int lms_socket_clearsq(MSocket *m, ssize_t len);
extern int lms_socket_freerq(MSocket *m);

/* dns.c */
extern void lms_dns_cleancache(void);
extern int lms_dns_lookup(const char *h, Abstract *a);
extern int lms_dns_findrev(MSocket *m);
extern int lms_dns_getip(const char *host, char *buf, size_t buf_len);
extern int lms_dns_gethost(const char *ip, char *buf, size_t buf_len);

/* mux.c */
extern int lms_mux_addfd(MSocket *ms, int fd, unsigned short t);
extern int lms_mux_remfd(int fd);
extern void lms_mux_setprio(MSocket *s, short prio);

/* ssl.c */
extern int lms_ssl_startsock(MSocket *m);
extern int lms_ssl_closesock(MSocket *m);
extern int lms_ssl_stopsock(MSocket *m);
extern int lms_ssl_unclean(MSocket *m);
extern char *lms_ssl_getclientinfo(MSocket *m);

/*
**
** MACROS
**
*/

/* These macros set various flags on a socket */
# define LMS_SetTimeout(s, t)		((s)->conn_to = (t))
# define LMS_SetBlocking(s)		((s)->opts |= LMSOPTION_BLOCK)
# define LMS_SetAllowIdle(s)		((s)->opts |= LMSOPTION_ALLOWIDLE)
# define LMS_SetCWait(s)		((s)->opts |= LMSOPTION_CWAIT)
# define LMS_SetSSL(s)			((s)->opts |= LMSOPTION_SSL)
# define LMS_SetSSLUnClean(s)		((s)->opts |= LMSOPTION_UCREP)
# define LMS_SetSocks(s)		((s)->opts |= LMSOPTION_SOCKS)

/* These macros evaluate as true if the circumstance described is true */
# define LMS_IsConnected(s)		((s)->flags & LMSFLG_CONNECTED)
# define LMS_IsWaiting(s)		(((s)->flags & LMSFLG_WAITCONN) || ((s)->flags & LMSFLG_WAITDNS) || ((s)->flags & LMSFLG_WAITIDENT))
# define LMS_ProxyReady(s)		(((s)->flags & LMSFLG_CONNECTED) && ((s)->flags & LMSFLG_PROXIED))

/* The following macro sends out the contents of the sockets sendQ */
# define LMS_SendQueue(s)		(s)->func_w((s))

#endif /* INCLUDED_MSOCKET_H */
