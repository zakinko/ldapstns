/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * The BER encoding and decoding LDAP is built out of.
 *
 * Only the subset RFC 4511 actually uses is here, which is a good deal smaller
 * than BER in general: definite lengths only, single byte tags only, and no
 * constructed octet strings.  Everything outside that subset is rejected
 * rather than interpreted.  This code reads what an unauthenticated client
 * sent us, so the interesting property is not what it can parse but what it
 * refuses to.
 *
 * The decoder never advances its cursor on a failed read.  Each accessor works
 * on a copy of the cursor and commits it only once the whole value has been
 * read successfully, so a caller that tries one tag, fails, and tries another
 * is looking at the same bytes both times - which is exactly what parsing a
 * CHOICE requires.
 */
#include <errno.h>
#include <stdarg.h>

#include "ldapstns.h"

/*
 * Encoding
 *
 * The buffer carries a sticky error flag rather than returning a status from
 * every call.  Building a message means dozens of appends, each of which can
 * only fail by running out of memory; checking each one would bury the shape
 * of the message in error handling, so instead the flag is set on the first
 * failure, every later append is a no-op, and the caller checks once at the
 * end.
 */
void
bbuf_init(bbuf *b)
{
	memset(b, 0, sizeof(*b));
}

void
bbuf_free(bbuf *b)
{
	free(b->p);
	memset(b, 0, sizeof(*b));
}

static int
bbuf_reserve(bbuf *b, size_t need)
{
	size_t cap;
	uint8_t *p;

	if (b->error)
		return 0;
	if (b->cap - b->len >= need)
		return 1;

	cap = (b->cap != 0) ? b->cap : 256;
	while (cap - b->len < need) {
		if (cap > SIZE_MAX / 2) {
			b->error = 1;
			return 0;
		}
		cap *= 2;
	}
	if ((p = realloc(b->p, cap)) == NULL) {
		b->error = 1;
		return 0;
	}
	b->p = p;
	b->cap = cap;
	return 1;
}

void
bbuf_bytes(bbuf *b, const void *v, size_t len)
{
	if (!bbuf_reserve(b, len))
		return;
	memcpy(b->p + b->len, v, len);
	b->len += len;
}

/* A definite length: short form below 128, long form above it. */
static void
bbuf_length(bbuf *b, size_t len)
{
	uint8_t hdr[sizeof(size_t) + 1];
	size_t n, i;

	if (len < 0x80) {
		hdr[0] = (uint8_t)len;
		bbuf_bytes(b, hdr, 1);
		return;
	}

	for (n = 0; (len >> (n * 8)) != 0; n++)
		;
	hdr[0] = (uint8_t)(0x80 | n);
	for (i = 0; i < n; i++)
		hdr[1 + i] = (uint8_t)(len >> ((n - 1 - i) * 8));
	bbuf_bytes(b, hdr, n + 1);
}

void
bbuf_tlv(bbuf *b, uint8_t tag, const void *v, size_t len)
{
	bbuf_bytes(b, &tag, 1);
	bbuf_length(b, len);
	bbuf_bytes(b, v, len);
}

/*
 * Wrap an already built buffer in a tag.  This is how nesting is done: the
 * inner structure is complete before its length is known, which is the whole
 * awkwardness of BER.  An error in the inner buffer is carried outwards, so a
 * failure five levels down is still visible at the top.
 */
void
bbuf_wrap(bbuf *b, uint8_t tag, const bbuf *inner)
{
	if (inner->error)
		b->error = 1;
	bbuf_tlv(b, tag, inner->p, inner->len);
}

/*
 * A BER integer is two's complement, big endian, in the fewest bytes that
 * still carry the sign - so a leading 0x00 is required before a byte with its
 * top bit set, and forbidden anywhere else.
 */
void
bbuf_int(bbuf *b, uint8_t tag, long v)
{
	uint8_t out[sizeof(long)];
	size_t n = 0;
	unsigned long u = (unsigned long)v;
	int i;

	for (i = (int)sizeof(long) - 1; i >= 0; i--) {
		uint8_t byte = (uint8_t)(u >> (i * 8));

		if (n == 0) {
			/* Skip the padding this byte would be. */
			if (v >= 0 && byte == 0x00 && i > 0 &&
			    ((uint8_t)(u >> ((i - 1) * 8)) & 0x80) == 0)
				continue;
			if (v < 0 && byte == 0xff && i > 0 &&
			    ((uint8_t)(u >> ((i - 1) * 8)) & 0x80) != 0)
				continue;
		}
		out[n++] = byte;
	}
	if (n == 0)
		out[n++] = 0x00;
	bbuf_tlv(b, tag, out, n);
}

void
bbuf_str(bbuf *b, uint8_t tag, const char *s)
{
	if (s == NULL)
		s = "";
	bbuf_tlv(b, tag, s, strlen(s));
}

void
bbuf_bool(bbuf *b, uint8_t tag, int v)
{
	uint8_t byte = v ? 0xff : 0x00;

	bbuf_tlv(b, tag, &byte, 1);
}

/*
 * Decoding
 */
void
ber_init(ber *b, const void *buf, size_t len)
{
	b->buf = buf;
	b->len = len;
	b->pos = 0;
}

int
ber_end(const ber *b)
{
	return b->pos >= b->len;
}

int
ber_peek(const ber *b, uint8_t *tag)
{
	if (b->pos >= b->len)
		return 0;
	*tag = b->buf[b->pos];
	return 1;
}

/*
 * Read one tag-length-value.  On success *val is a cursor over the contents
 * and this cursor has stepped past the whole thing; on failure neither has
 * moved.
 */
int
ber_tlv(ber *b, uint8_t *tag, ber *val)
{
	size_t pos = b->pos;
	size_t len, n, i;
	uint8_t t, first;

	if (pos + 2 > b->len)
		return 0;

	t = b->buf[pos++];
	/*
	 * A tag number of 31 means the number continues into the following
	 * bytes.  LDAP has no such tag, so this is a message we would only ever
	 * be guessing at the meaning of.
	 */
	if ((t & 0x1f) == 0x1f)
		return 0;

	first = b->buf[pos++];
	if ((first & 0x80) == 0) {
		len = first;
	} else {
		n = first & 0x7f;
		/*
		 * n == 0 is the indefinite length form, which is terminated by
		 * a pair of zero bytes somewhere later in the stream.  DER
		 * forbids it and LDAP does not use it, and accepting it would
		 * mean scanning ahead through data we have not validated.
		 */
		if (n == 0 || n > sizeof(size_t))
			return 0;
		if (pos + n > b->len)
			return 0;
		len = 0;
		for (i = 0; i < n; i++)
			len = (len << 8) | b->buf[pos++];
	}

	if (len > b->len - pos)
		return 0;

	if (tag != NULL)
		*tag = t;
	if (val != NULL)
		ber_init(val, b->buf + pos, len);
	b->pos = pos + len;
	return 1;
}

int
ber_expect(ber *b, uint8_t tag, ber *val)
{
	ber save = *b;
	uint8_t got;

	if (!ber_tlv(b, &got, val))
		return 0;
	if (got != tag) {
		*b = save;
		return 0;
	}
	return 1;
}

int
ber_int(ber *b, uint8_t tag, long *v)
{
	ber save = *b;
	ber val;
	unsigned long u;
	size_t i;

	if (!ber_expect(b, tag, &val))
		return 0;
	if (val.len == 0 || val.len > sizeof(long)) {
		*b = save;
		return 0;
	}

	/* Sign extend from the first byte, then shift the rest in. */
	u = (val.buf[0] & 0x80) ? ~0UL : 0UL;
	for (i = 0; i < val.len; i++)
		u = (u << 8) | val.buf[i];

	*v = (long)u;
	return 1;
}

int
ber_bool(ber *b, uint8_t tag, int *v)
{
	ber save = *b;
	ber val;

	if (!ber_expect(b, tag, &val))
		return 0;
	if (val.len != 1) {
		*b = save;
		return 0;
	}
	*v = (val.buf[0] != 0);
	return 1;
}

/*
 * Read an octet string as a C string.
 *
 * An LDAP octet string is a byte string and may legitimately contain a NUL.
 * Nothing downstream of here - a DN comparison, an attribute name, a value
 * written into a reply - would handle one correctly, and silently truncating
 * at it is how a filter comes to match something it does not say it matches.
 * So an embedded NUL is refused outright.
 */
int
ber_str(ber *b, uint8_t tag, char **s)
{
	ber save = *b;
	ber val;
	char *out;

	if (!ber_expect(b, tag, &val))
		return 0;
	if (memchr(val.buf, '\0', val.len) != NULL) {
		*b = save;
		return 0;
	}
	if ((out = malloc(val.len + 1)) == NULL) {
		*b = save;
		return 0;
	}
	memcpy(out, val.buf, val.len);
	out[val.len] = '\0';
	*s = out;
	return 1;
}
