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

#ifndef INCLUDED_MSOCKETUTILS_H
# define INCLUDED_MSOCKETUTILS_H     1

# define stringtoint(x)			(int)strtol((x), (char **)NULL, 10)
# define stringtolong(x)		strtol((x), (char **)NULL, 10)
# define stringtouint(x)		(unsigned int)strtoul((x), (char **)NULL, 10)
# define stringtoulong(x)		strtoul((x), (char **)NULL, 10)
# define stringtofloat(x)		strtof((x), (char **)NULL)

/* file.c */
extern size_t lms_file_readln(int fd, char *buf, size_t buf_len);
extern int lms_file_writepid(const char *fn, pid_t pid);
extern int8_t lms_file_icanrw(struct stat *fs);
extern int8_t lms_file_icanr(struct stat *fs);

/* str.c */
extern void lms_str_memnuke(volatile void *b, size_t sz);
extern void lms_str_copy(void *src, void *dst, size_t len);
extern void lms_str_ocopy(void *src, void *dst, size_t len, uint32_t offset);

/* base64.c */
  /* Note here: strlen() is used, so the string must be null-terminated to use this macro... */
# define lms_base64_dstrlen(x)			(3 * (strlen((x)) / 4 + 1))
  /* This one is safe if it's not a null-terminated string, just pass the length of the data to be decoded. */
# define lms_base64_dlen(x)			(3 * ((x) / 4 + 1))
extern unsigned char *lms_base64_encode(unsigned char *src, unsigned char *dst, size_t len);
extern unsigned char *lms_base64_decode(unsigned char *src, unsigned char *dst);

#endif /* INCLUDED_MSOCKETUTILS_H */
