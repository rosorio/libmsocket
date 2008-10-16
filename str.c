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

#if defined(HAVE_SYS_ENDIAN_H)
# include <sys/endian.h>
#elif defined(HAVE_MACHINE_ENDIAN_H)
# include <machine/endian.h>
#endif /* defined(HAVE_SYS_ENDIAN_H) ; defined(HAVE_MACHINE_ENDIAN_H) */

#if !defined(BYTE_ORDER)
# error "BYTE_ORDER is not defined - please send info about your platform and grep for it to let me know what file needs to be included."
#endif /* !defined(BYTE_ORDER) */


/*
 * lms_str_memnuke() clears a memory buffer for real
 *           cast b to (volatile) when calling
 *
 * b = pointer to memory buffer to be cleared
 * sz = size of buffer to be cleared
 *
 */
void lms_str_memnuke(volatile void *b, size_t sz)
{
	volatile char *xb;

	if (!b)
	{
		return;
	}

	for (xb = (volatile char *)b; sz; xb[--sz] = 0);
	return;
}

/*
 * lms_str_copy() copies ``len'' bytes from src to dst
 *
 * src = the source memory buffer
 * dst = the destination memory buffer
 * len = the exact number of bytes to copy
 *
 */
void lms_str_copy(void *src, void *dst, size_t len)
{
	char *x_src;
	char *x_dst;
	register unsigned int i;

	/* Wait... isn't this what f'ing memcpy() does? */
	if (!src || !dst || (len == 0) || (src == dst))
	{
		return;
	}

	x_src = src;
	x_dst = dst;

	for (i = 0; i < len; ++i)
	{
		x_dst[i] = x_src[i];
	}
}

/*
 * lms_str_ocopy() copies ``len'' bytes from src to dst, starting at ``offset'' into src
 *
 * src = the source memory buffer
 * dst = the destination memory buffer
 * len = the exact number of bytes to copy
 * offset = the byte in src at which to begin copying
 *
 */
void lms_str_ocopy(void *src, void *dst, size_t len, unsigned int offset)
{
	char *x_src;
	char *x_dst;
	register unsigned int i;

	if (!src || !dst || (len == 0) || (src == dst))
	{
		return;
	}

	x_src = src;
	x_dst = dst;

	for (i = offset; i < len; ++i)
	{
		x_dst[i - offset] = x_src[i];
	}
}

/*
 * lms_str_getbytes() returns a structure containing the bytes, in network byte order, of an ip/port combo
 *
 * ip = the ip address
 * port = the port
 *
 */
lms_addrbytes *lms_str_getbytes(in_addr_t ip, int port)
{
	lms_addrbytes *a;

	a = (lms_addrbytes *)calloc(1, sizeof(lms_addrbytes));
	if (!a)
	{
		return((lms_addrbytes *)NULL);
	}

	if ((ip > 0) && (ip != IN_ADDR_NONE))
	{
	}

#if (BYTE_ORDER == BIG_ENDIAN)
	if (port > 0)
	{
		a->portA = ;
		a->portB = ;
	}
#else
	if (port > 0)
	{
		a->portA = ;
		a->portB = ;
	}
#endif /* (BYTE_ORDER == BIG_ENDIAN) */

	return(a);
}
