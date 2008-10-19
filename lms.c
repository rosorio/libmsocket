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

char *lms_proxy_ip;
int lms_proxy_port;
unsigned short lms_proxy_type;

static time_t _lms_loop_lastrun = 0;


/*
 * lms_loop() is our main event loop
 *
 */
int lms_loop()
{
	if (_lms_loop_lastrun < time(NULL))
	{
		lms_socket_housekeeping();
		lms_dns_cleancache();
#ifdef LMS_THROTTLE_ENABLE
		lms_throttle_expire();
#endif /* LMS_THROTTLE_ENABLE */
		_lms_loop_lastrun = time(NULL);
	}

	event_base_loop(lms_mux_evtb, EVLOOP_ONCE|EVLOOP_NONBLOCK);

	return(0);
}

/*
 * lms_init() initializes all components of libmsocket
 *
 */
int lms_init(unsigned char print)
{
	if (lms_socket_init() < 0)
	{
		if (print > 0)
		{
			fprintf(stdout, "MSocket initialization failed: %s\n", strerror(errno));
		}
		return(-1);
	}
	if (lms_mux_init() < 0)
	{
		if (print > 0)
		{
			fprintf(stdout, "MUX initialization failed: %s\n", strerror(errno));
		}
		return(-1);
	}
	if (lms_dns_init() < 0)
	{
		if (print > 0)
		{
			fprintf(stdout, "DNS initialization failed: %s\n", strerror(errno));
		}
		return(-1);
	}
	if (lms_ssl_init() < 0)
	{
		if (print > 0)
		{
			fprintf(stdout, "SSL initialization failed: %s\n", strerror(errno));
		}
		return(-1);
	}

	return(0);
}

/*
 * lms_version_int() returns the version of libmsocket in an integer format
 *
 */
int lms_version_int()
{
	return(LMS_VERSION_INT);
}

/*
 * lms_version() returns the version of libmsocket
 *
 */
char *lms_version()
{
	return(LMS_VERSION);
}

/*
 * lms_proxyset() sets a proxy to be used for all outbound connections
 *
 * type = the flavor of proxy it is (LMSPROXY_*)
 * host = the hostname or IP address of the proxy
 * port = the TCP port number on which it resides
 *
 */
int lms_proxyset(unsigned short type, char *host, int port)
{
	in_addr_t proxyaddr;

	if (!host || (type <= 0) || (port <= 0))
	{
		errno = EINVAL;
		return(-1);
	}

	proxyaddr = inet_addr(host);
	if (proxyaddr == INADDR_NONE)
	{
		/* Perform DNS lookup */
		return(-1);	/* Instead of just bailing - for now, let the caller do the DNS lookup - later, support a DNS name. */
	}
	else
	{
		lms_proxy_ip = (char *)NULL;
#ifdef LMS_HARDCORE_ALLOC
		while (!lms_proxy_ip)
		{
			lms_proxy_ip = (char *)malloc(LMS_LEN_V4ADDR + 1);
		}
#else
		lms_proxy_ip = (char *)malloc(LMS_LEN_V4ADDR + 1);
		if (!lms_proxy_ip)
		{
			return(-1);
		}
#endif /* LMS_HARDCORE_ALLOC */

		memset(lms_proxy_ip, 0, (LMS_LEN_V4ADDR + 1));
		snprintf(lms_proxy_ip, (LMS_LEN_V4ADDR + 1), "%s", host);
	}

	lms_proxy_port = port;
	lms_proxy_type = type;
	return(0);
}

/*
 * lms_proxyclear() clears the proxy setting, returning msocket to normal operation
 *
 */
int lms_proxyclear()
{
	if (lms_proxy_type == LMSPROXY_NONE)
	{
		return(-1);
	}

	lms_proxy_type = LMSPROXY_NONE;
	lms_proxy_port = 0;
	if (lms_proxy_ip)
	{
		free(lms_proxy_ip);
	}
	lms_proxy_ip = (char *)NULL;

	return(0);
}
