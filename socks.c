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

#include <msocket-internal.h>


/*
 * lms_socks_startsock() initiates a socks5 connection on a socket
 *
 * m = the socket which will be making a Socks5-proxied connection
 *
 */
int lms_socks_startsock(MSocket *m)
{
	m->func_p = lms_socks_hdshkread;
	m->func_w = lms_socks_hdshkwrite;

	m->flags |= LMSFLG_SOCKSNEEDINIT;
	m->flags |= LMSFLG_SOCKSWAITCONN;

	return(0);
}

/*
 * lms_socks_hdshkread() is a read func for an MSocket which has not completed the Socks5 negotiation
 *
 * m = the socket on which to attempt to complete the handshake
 *
 */
int lms_socks_hdshkread(MSocket *m)
{
	if (!m)
	{
		errno = EINVAL;
		return(-1);
	}

	if (m->flags & LMSFLG_SOCKSWAITINIT)
	{
		if (m->recvQ_len < 2)
		{
			return(0);
		}

		if (m->recvQ[0] != 5)
		{
			m->func_e(m);
			return(-1);
		}

		if (m->recvQ[1] == 0)
		{
			m->flags |= LMSFLG_SOCKSNEEDCONN;
		}
		else if (m->recvQ[1] == 2)
		{
			m->flags |= LMSFLG_SOCKSNEEDAUTH;
		}
		else
		{
			m->func_e(m);
			return(-1);
		}

		m->flags &= ~LMSFLG_SOCKSWAITINIT;
		lms_socket_freerq(m);

		lms_socks_hdshkwrite(m);
	}
	else if (m->flags & LMSFLG_SOCKSWAITDONE)
	{
		m->flags |= LMSFLG_PROXIED;
		lms_socket_freerq(m);
	}

	return(0);
}

/*
 * lms_socks_hdshkwrite() is a write func for an MSocket which has not completed the Socks5 negotiation
 *
 * m = the socket on which to attempt to complete the handshake
 *
 */
int lms_socks_hdshkwrite(MSocket *m)
{
	if (!m)
	{
		errno = EINVAL;
		return(-1);
	}

	if (m->flags & LMSFLG_SOCKSNEEDINIT)
	{
		unsigned char *outbuf;
		size_t l;

		l = 4;

		outbuf = (unsigned char *)NULL;
#ifdef LMS_HARDCORE_ALLOC
		while (!outbuf)
		{
			outbuf = (unsigned char *)malloc(l);
		}
#else
		outbuf = (unsigned char *)malloc(l);
		if (!outbuf)
		{
			return(-1);
		}
#endif /* LMS_HARDCORE_ALLOC */

		outbuf[0] = 5;	/* Socks5 */
		outbuf[1] = 2;	/* Support 2 authentication methods */
		outbuf[2] = 0;	/* No authentication, or... */
		outbuf[3] = 2;	/* Plain username/password authentication */

		lms_socket_appendq(m, outbuf, l);
		lms_socket_flushq(m);
		free(outbuf);

		m->flags &= ~LMSFLG_SOCKSNEEDINIT;
		m->flags |= LMSFLG_SOCKSWAITINIT;
	}
	else if (m->flags & LMSFLG_SOCKSNEEDAUTH)
	{
		unsigned char *outbuf;
		size_t l;

		l = ;

		outbuf = (unsigned char *)NULL;
#ifdef LMS_HARDCORE_ALLOC
		while (!outbuf)
		{
			outbuf = (unsigned char *)malloc(l);
		}
#else
		outbuf = (unsigned char *)malloc(l);
		if (!outbuf)
		{
			return(-1);
		}
#endif /* LMS_HARDCORE_ALLOC */

		lms_socket_appendq(m, outbuf, l);
		lms_socket_flushq(m);
		free(outbuf);

		m->flags &= ~LMSFLG_SOCKSNEEDAUTH;
		m->flags |= LMSFLG_SOCKSWAITAUTH;
	}
	else if (m->flags & LMSFLG_SOCKSNEEDCONN)
	{
		unsigned char *outbuf;
		size_t l;
		in_addr_t addr;
		lms_addrbytes *ab;

		addr = inet_addr(m->remotehost);
		if (addr == INADDR_NONE)
		{
			l = (7 + strlen(m->remotehost));
		}
		else
		{
			l = 10;
		}

		outbuf = (unsigned char *)NULL;
#ifdef LMS_HARDCORE_ALLOC
		while (!outbuf)
		{
			outbuf = (unsigned char *)malloc(l);
		}
#else
		outbuf = (unsigned char *)malloc(l);
		if (!outbuf)
		{
			return(-1);
		}
#endif /* LMS_HARDCORE_ALLOC */

		outbuf[0] = 5;
		outbuf[1] = 1;
		outbuf[2] = 0;

		if (addr == INADDR_NONE)
		{
			unsigned short i;

			ab = lms_str_getbytes(INADDR_NONE, m->remoteport);
			if (!ab)
			{
				free(outbuf);
				return(-1);
			}

			outbuf[3] = 3;

			/* Hostname */
			outbuf[4] = (unsigned char)strlen(m->remotehost);
			for (i = 0; m->remotehost[i] != '\0'; ++i)
			{
				outbuf[i + 5] = m->remotehost[i];
			}
			i += 5;

			/* Port */
			outbuf[i] = ab->portA;
			i++;
			outbuf[i] = ab->portB;
			i++;

			free(ab);
		}
		else
		{
			ab = lms_str_getbytes(addr, m->remoteport);
			if (!ab)
			{
				free(outbuf);
				return(-1);
			}
			outbuf[3] = 1;

			/* IP addr */
			outbuf[4] = ab->ipA;
			outbuf[5] = ab->ipB;
			outbuf[6] = ab->ipC;
			outbuf[7] = ab->ipD;

			/* Port */
			outbuf[8] = ab->portA;
			outbuf[9] = ab->portB;

			free(ab);
		}

		lms_socket_appendq(m, outbuf, l);
		lms_socket_flushq(m);
		free(outbuf);

		m->flags &= ~LMSFLG_SOCKSNEEDCONN;
		m->flags |= LMSFLG_SOCKSWAITDONE;
	}
	else
	{
		lms_socket_flushq(m);
	}

	return(0);
}
