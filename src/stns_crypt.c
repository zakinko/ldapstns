/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * Checking a password against the hash STNS holds for a user.
 *
 * This exists because the systems this runs on cannot do it.  STNS
 * deployments are configured from Linux and the hashes in them are almost
 * always SHA-512 crypt - "$6$..." - and:
 *
 *	macOS		crypt(3) supports traditional DES and nothing else.
 *			Worse, it does not say so: handed "$6$salt$..." it
 *			takes "$6" as a two character salt and returns a
 *			perfectly ordinary looking DES hash.  A caller that
 *			compared that with what it was given would reject every
 *			password and have no idea why.
 *	OpenBSD		crypt_checkpass(3) does bcrypt, which is the right
 *			answer for a hash generated on OpenBSD and no answer at
 *			all for one generated anywhere else.
 *
 * So SHA-256 crypt and SHA-512 crypt are implemented here, to the definition
 * Ulrich Drepper published, and tests/crypt_test.c checks them against the
 * vectors in it.  bcrypt is handed to the system's crypt(3) where that works
 * and refused where it does not, rather than being reimplemented: unlike these
 * two it needs a whole Blowfish, and a machine holding bcrypt hashes is one
 * whose crypt(3) understands them.
 *
 * Everything here fails closed.  Every path that is not a positive match -
 * an unknown prefix, a malformed hash, a locked account, an allocation
 * failure - returns "no", and the comparison itself is timing safe.
 */
/* Before <string.h>, for memset_s(3) on the one system that has it. */
#define __STDC_WANT_LIB_EXT1__ 1

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "stns.h"

/*
 * Wipe a buffer in a way the compiler is not allowed to remove.
 *
 * Five systems, three spellings.  OpenBSD, FreeBSD and DragonFly have
 * explicit_bzero(3); NetBSD calls the same idea explicit_memset(3) and does
 * not have the other name at all; macOS has neither and offers memset_s(3).
 * A plain memset(3) is not a substitute - the whole point is a write to memory
 * that is dead immediately afterwards, which is precisely what a compiler is
 * entitled to delete.
 */
static void
stns_zero(void *p, size_t n)
{
#if defined(__APPLE__)
	(void)memset_s(p, n, 0, n);
#elif defined(__NetBSD__)
	(void)explicit_memset(p, 0, n);
#else
	explicit_bzero(p, n);
#endif
}

/*
 * Compare two buffers in time that does not depend on where they first differ.
 *
 * Same story as the wipe above, and the same reason for not writing it out
 * here: a loop that accumulates differences into one variable is exactly what
 * a compiler may turn back into an early exit.  NetBSD spells it
 * consttime_memequal(3) and, unlike the others, returns true when the buffers
 * are equal - so the sense is inverted here rather than at the call site,
 * where getting it backwards would accept every password.
 */
static int
stns_bcmp(const void *a, const void *b, size_t n)
{
#ifdef __NetBSD__
	return !consttime_memequal(a, b, n);
#else
	return timingsafe_bcmp(a, b, n);
#endif
}

/*
 * SHA-256 and SHA-512, to FIPS 180-4.
 *
 * Written out rather than taken from the system because the four systems this
 * library builds on spell it four different ways - <sha2.h> with SHA512Init on
 * OpenBSD, <sha2.h> with SHA512_Init on NetBSD, <sha512.h> on FreeBSD and
 * CommonCrypto on macOS - and because a hash with published test vectors is
 * the one piece of cryptography it is reasonable to carry.  tests/crypt_test.c
 * checks both against the vectors in the standard.
 */
#define SHA256_BLOCK 64
#define SHA256_DIGEST 32
#define SHA512_BLOCK 128
#define SHA512_DIGEST 64

struct sha256 {
	uint32_t h[8];
	uint64_t len;
	uint8_t buf[SHA256_BLOCK];
	size_t used;
};

struct sha512 {
	uint64_t h[8];
	uint64_t len;
	uint8_t buf[SHA512_BLOCK];
	size_t used;
};

static const uint32_t k256[64] = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
	0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
	0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
	0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70,
	0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa,
	0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

static const uint64_t k512[80] = { 0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
	0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL,
	0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL,
	0x550c7dc3d5ffb4e2ULL, 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
	0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL,
	0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL,
	0x76f988da831153b5ULL, 0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
	0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL,
	0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL,
	0x53380d139d95b3dfULL, 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
	0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL,
	0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL,
	0x106aa07032bbd1b8ULL, 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
	0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL,
	0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL,
	0x8cc702081a6439ecULL, 0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
	0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL,
	0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL,
	0x1b710b35131c471bULL, 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
	0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL,
	0x6c44198c4a475817ULL };

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static void
sha256_block(struct sha256 *c, const uint8_t *p)
{
	uint32_t w[64], a, b, cc, d, e, f, g, h, t1, t2;
	int i;

	for (i = 0; i < 16; i++)
		w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) | ((uint32_t)p[i * 4 + 2] << 8) |
		    p[i * 4 + 3];
	for (; i < 64; i++) {
		uint32_t s0 = ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10);

		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	a = c->h[0];
	b = c->h[1];
	cc = c->h[2];
	d = c->h[3];
	e = c->h[4];
	f = c->h[5];
	g = c->h[6];
	h = c->h[7];

	for (i = 0; i < 64; i++) {
		t1 = h + (ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25)) + ((e & f) ^ (~e & g)) + k256[i] + w[i];
		t2 = (ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22)) + ((a & b) ^ (a & cc) ^ (b & cc));
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = cc;
		cc = b;
		b = a;
		a = t1 + t2;
	}

	c->h[0] += a;
	c->h[1] += b;
	c->h[2] += cc;
	c->h[3] += d;
	c->h[4] += e;
	c->h[5] += f;
	c->h[6] += g;
	c->h[7] += h;
}

static void
sha512_block(struct sha512 *c, const uint8_t *p)
{
	uint64_t w[80], a, b, cc, d, e, f, g, h, t1, t2;
	int i, j;

	for (i = 0; i < 16; i++) {
		w[i] = 0;
		for (j = 0; j < 8; j++)
			w[i] = (w[i] << 8) | p[i * 8 + j];
	}
	for (; i < 80; i++) {
		uint64_t s0 = ROR64(w[i - 15], 1) ^ ROR64(w[i - 15], 8) ^ (w[i - 15] >> 7);
		uint64_t s1 = ROR64(w[i - 2], 19) ^ ROR64(w[i - 2], 61) ^ (w[i - 2] >> 6);

		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	a = c->h[0];
	b = c->h[1];
	cc = c->h[2];
	d = c->h[3];
	e = c->h[4];
	f = c->h[5];
	g = c->h[6];
	h = c->h[7];

	for (i = 0; i < 80; i++) {
		t1 = h + (ROR64(e, 14) ^ ROR64(e, 18) ^ ROR64(e, 41)) + ((e & f) ^ (~e & g)) + k512[i] + w[i];
		t2 = (ROR64(a, 28) ^ ROR64(a, 34) ^ ROR64(a, 39)) + ((a & b) ^ (a & cc) ^ (b & cc));
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = cc;
		cc = b;
		b = a;
		a = t1 + t2;
	}

	c->h[0] += a;
	c->h[1] += b;
	c->h[2] += cc;
	c->h[3] += d;
	c->h[4] += e;
	c->h[5] += f;
	c->h[6] += g;
	c->h[7] += h;
}

static void
sha256_init(struct sha256 *c)
{
	static const uint32_t iv[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
		0x1f83d9ab, 0x5be0cd19 };

	memcpy(c->h, iv, sizeof(iv));
	c->len = 0;
	c->used = 0;
}

static void
sha512_init(struct sha512 *c)
{
	static const uint64_t iv[8] = { 0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
		0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL,
		0x5be0cd19137e2179ULL };

	memcpy(c->h, iv, sizeof(iv));
	c->len = 0;
	c->used = 0;
}

static void
sha256_update(struct sha256 *c, const void *data, size_t len)
{
	const uint8_t *p = data;

	c->len += len;
	while (len > 0) {
		size_t n = SHA256_BLOCK - c->used;

		if (n > len)
			n = len;
		memcpy(c->buf + c->used, p, n);
		c->used += n;
		p += n;
		len -= n;
		if (c->used == SHA256_BLOCK) {
			sha256_block(c, c->buf);
			c->used = 0;
		}
	}
}

static void
sha512_update(struct sha512 *c, const void *data, size_t len)
{
	const uint8_t *p = data;

	c->len += len;
	while (len > 0) {
		size_t n = SHA512_BLOCK - c->used;

		if (n > len)
			n = len;
		memcpy(c->buf + c->used, p, n);
		c->used += n;
		p += n;
		len -= n;
		if (c->used == SHA512_BLOCK) {
			sha512_block(c, c->buf);
			c->used = 0;
		}
	}
}

static void
sha256_final(struct sha256 *c, uint8_t out[SHA256_DIGEST])
{
	uint64_t bits = c->len * 8;
	int i;

	c->buf[c->used++] = 0x80;
	if (c->used > SHA256_BLOCK - 8) {
		memset(c->buf + c->used, 0, SHA256_BLOCK - c->used);
		sha256_block(c, c->buf);
		c->used = 0;
	}
	memset(c->buf + c->used, 0, SHA256_BLOCK - 8 - c->used);
	for (i = 0; i < 8; i++)
		c->buf[SHA256_BLOCK - 1 - i] = (uint8_t)(bits >> (i * 8));
	sha256_block(c, c->buf);

	for (i = 0; i < 8; i++) {
		out[i * 4] = (uint8_t)(c->h[i] >> 24);
		out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
		out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
		out[i * 4 + 3] = (uint8_t)c->h[i];
	}
	stns_zero(c, sizeof(*c));
}

static void
sha512_final(struct sha512 *c, uint8_t out[SHA512_DIGEST])
{
	uint64_t bits = c->len * 8;
	int i, j;

	c->buf[c->used++] = 0x80;
	if (c->used > SHA512_BLOCK - 16) {
		memset(c->buf + c->used, 0, SHA512_BLOCK - c->used);
		sha512_block(c, c->buf);
		c->used = 0;
	}
	memset(c->buf + c->used, 0, SHA512_BLOCK - 16 - c->used);
	/* The length is 128 bits; the top 64 of them are always zero here. */
	memset(c->buf + SHA512_BLOCK - 16, 0, 8);
	for (i = 0; i < 8; i++)
		c->buf[SHA512_BLOCK - 1 - i] = (uint8_t)(bits >> (i * 8));
	sha512_block(c, c->buf);

	for (i = 0; i < 8; i++) {
		for (j = 0; j < 8; j++)
			out[i * 8 + j] = (uint8_t)(c->h[i] >> ((7 - j) * 8));
	}
	stns_zero(c, sizeof(*c));
}

void
stns_sha256(const void *data, size_t len, uint8_t out[32])
{
	struct sha256 c;

	sha256_init(&c);
	sha256_update(&c, data, len);
	sha256_final(&c, out);
}

void
stns_sha512(const void *data, size_t len, uint8_t out[64])
{
	struct sha512 c;

	sha512_init(&c);
	sha512_update(&c, data, len);
	sha512_final(&c, out);
}

/*
 * The crypt alphabet, which is not the base64 anybody else uses: the digits
 * come before the letters and the first two characters are '.' and '/'.
 */
static const char b64[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/*
 * Three bytes to four characters, least significant first, which is the other
 * way round from base64 proper.
 */
static void
b64_from_24bit(char **out, uint8_t a, uint8_t b, uint8_t c, int n)
{
	uint32_t w = ((uint32_t)a << 16) | ((uint32_t)b << 8) | c;
	int i;

	for (i = 0; i < n; i++) {
		*(*out)++ = b64[w & 0x3f];
		w >>= 6;
	}
}

/*
 * The order the digest bytes are emitted in, which is a permutation and not a
 * sequence.  Written out as a table rather than as code, because it is data:
 * every third entry is the one that would be a run if it were anything else.
 */
static const uint8_t order512[21][3] = { { 0, 21, 42 }, { 22, 43, 1 }, { 44, 2, 23 }, { 3, 24, 45 }, { 25, 46, 4 },
	{ 47, 5, 26 }, { 6, 27, 48 }, { 28, 49, 7 }, { 50, 8, 29 }, { 9, 30, 51 }, { 31, 52, 10 }, { 53, 11, 32 },
	{ 12, 33, 54 }, { 34, 55, 13 }, { 56, 14, 35 }, { 15, 36, 57 }, { 37, 58, 16 }, { 59, 17, 38 }, { 18, 39, 60 },
	{ 40, 61, 19 }, { 62, 20, 41 } };

static const uint8_t order256[10][3] = { { 0, 10, 20 }, { 21, 1, 11 }, { 12, 22, 2 }, { 3, 13, 23 }, { 24, 4, 14 },
	{ 15, 25, 5 }, { 6, 16, 26 }, { 27, 7, 17 }, { 18, 28, 8 }, { 9, 19, 29 } };

#define CRYPT_ROUNDS_DEFAULT 5000
#define CRYPT_ROUNDS_MIN 1000
#define CRYPT_ROUNDS_MAX 999999999
#define CRYPT_SALT_MAX 16

/*
 * SHA crypt, as published by Ulrich Drepper.
 *
 * The two variants are the same algorithm over a different hash and digest
 * length, so they are one function with a width parameter rather than two
 * near-identical ones - the places they differ are exactly the places the
 * specification says they differ.
 */
static int
sha_crypt(const char *password, const char *salt, size_t saltlen, unsigned long rounds, int explicit_rounds, int is512,
    char *out, size_t outlen)
{
	uint8_t a[SHA512_DIGEST], b[SHA512_DIGEST], dp[SHA512_DIGEST], ds[SHA512_DIGEST];
	uint8_t *p = NULL, *s = NULL;
	struct sha512 c512, alt512;
	struct sha256 c256, alt256;
	size_t dlen = is512 ? SHA512_DIGEST : SHA256_DIGEST;
	size_t plen = strlen(password);
	size_t i, cnt;
	char *o = out;
	int rv = STNS_NG;

/*
 * The two hashes have different type names, so the sequence below is written
 * once through these and instantiated twice rather than duplicated.
 */
#define H_INIT(ctx) (is512 ? sha512_init(&ctx##512) : sha256_init(&ctx##256))
#define H_UPDATE(ctx, d, n) (is512 ? sha512_update(&ctx##512, (d), (n)) : sha256_update(&ctx##256, (d), (n)))
#define H_FINAL(ctx, o) (is512 ? sha512_final(&ctx##512, (o)) : sha256_final(&ctx##256, (o)))

	/* B = H(password || salt || password) */
	H_INIT(c);
	H_UPDATE(c, password, plen);
	H_UPDATE(c, salt, saltlen);
	H_UPDATE(c, password, plen);
	H_FINAL(c, b);

	/* A = H(password || salt || B-repeated-to-plen || bits of plen) */
	H_INIT(c);
	H_UPDATE(c, password, plen);
	H_UPDATE(c, salt, saltlen);
	for (cnt = plen; cnt > dlen; cnt -= dlen)
		H_UPDATE(c, b, dlen);
	H_UPDATE(c, b, cnt);
	for (cnt = plen; cnt > 0; cnt >>= 1) {
		if (cnt & 1)
			H_UPDATE(c, b, dlen);
		else
			H_UPDATE(c, password, plen);
	}
	H_FINAL(c, a);

	/* P = first plen bytes of H(password repeated plen times), repeated. */
	H_INIT(alt);
	for (cnt = 0; cnt < plen; cnt++)
		H_UPDATE(alt, password, plen);
	H_FINAL(alt, dp);

	if ((p = malloc(plen + dlen)) == NULL)
		goto done;
	for (cnt = plen, i = 0; cnt >= dlen; cnt -= dlen, i += dlen)
		memcpy(p + i, dp, dlen);
	memcpy(p + i, dp, cnt);

	/* S = first saltlen bytes of H(salt repeated 16 + A[0] times). */
	H_INIT(alt);
	for (cnt = 0; cnt < (size_t)16 + a[0]; cnt++)
		H_UPDATE(alt, salt, saltlen);
	H_FINAL(alt, ds);

	if ((s = malloc(saltlen + dlen)) == NULL)
		goto done;
	for (cnt = saltlen, i = 0; cnt >= dlen; cnt -= dlen, i += dlen)
		memcpy(s + i, ds, dlen);
	memcpy(s + i, ds, cnt);

	/* The stretching loop, which is the whole cost of the scheme. */
	for (cnt = 0; cnt < rounds; cnt++) {
		H_INIT(c);
		if (cnt & 1)
			H_UPDATE(c, p, plen);
		else
			H_UPDATE(c, a, dlen);
		if (cnt % 3 != 0)
			H_UPDATE(c, s, saltlen);
		if (cnt % 7 != 0)
			H_UPDATE(c, p, plen);
		if (cnt & 1)
			H_UPDATE(c, a, dlen);
		else
			H_UPDATE(c, p, plen);
		H_FINAL(c, a);
	}

#undef H_INIT
#undef H_UPDATE
#undef H_FINAL

	/* "$6$" or "$5$", the rounds if they are not the default, the salt, "$". */
	i = (size_t)snprintf(out, outlen, "$%c$", is512 ? '6' : '5');
	if (i >= outlen)
		goto done;
	/*
	 * The round count is echoed back if and only if the setting spelled it
	 * out, whatever its value.  "$6$rounds=5000$..." is the default written
	 * down, and its hash still carries the "rounds=5000$" - so deciding
	 * this by comparing against the default produces a string that differs
	 * from the stored hash in its prefix alone, and every password on such
	 * an account is refused.
	 */
	if (explicit_rounds) {
		int n = snprintf(out + i, outlen - i, "rounds=%lu$", rounds);

		if (n < 0 || (size_t)n >= outlen - i)
			goto done;
		i += (size_t)n;
	}
	if (i + saltlen + 2 >= outlen)
		goto done;
	memcpy(out + i, salt, saltlen);
	i += saltlen;
	out[i++] = '$';
	o = out + i;

	if (is512) {
		if (i + 87 >= outlen)
			goto done;
		for (cnt = 0; cnt < 21; cnt++)
			b64_from_24bit(&o, a[order512[cnt][0]], a[order512[cnt][1]], a[order512[cnt][2]], 4);
		b64_from_24bit(&o, 0, 0, a[63], 2);
	} else {
		if (i + 44 >= outlen)
			goto done;
		for (cnt = 0; cnt < 10; cnt++)
			b64_from_24bit(&o, a[order256[cnt][0]], a[order256[cnt][1]], a[order256[cnt][2]], 4);
		b64_from_24bit(&o, 0, a[31], a[30], 3);
	}
	*o = '\0';
	rv = STNS_OK;

done:
	stns_zero(a, sizeof(a));
	stns_zero(b, sizeof(b));
	stns_zero(dp, sizeof(dp));
	stns_zero(ds, sizeof(ds));
	stns_zero(&c512, sizeof(c512));
	stns_zero(&c256, sizeof(c256));
	stns_zero(&alt512, sizeof(alt512));
	stns_zero(&alt256, sizeof(alt256));
	if (p != NULL)
		stns_zero(p, plen + dlen);
	if (s != NULL)
		stns_zero(s, saltlen + dlen);
	free(p);
	free(s);
	return rv;
}

/*
 * Split "$6$rounds=N$salt$..." into its parts.
 *
 * The salt stops at the next '$' or at sixteen characters, whichever comes
 * first, which is what the specification says and what every other
 * implementation does.
 */
static int
parse_setting(const char *hash, unsigned long *rounds, int *explicit_rounds, const char **salt, size_t *saltlen)
{
	const char *p = hash + 3;
	const char *end;

	*rounds = CRYPT_ROUNDS_DEFAULT;
	*explicit_rounds = 0;

	if (strncmp(p, "rounds=", 7) == 0) {
		*explicit_rounds = 1;
		char *stop;
		unsigned long v;

		errno = 0;
		v = strtoul(p + 7, &stop, 10);
		if (errno != 0 || stop == p + 7 || *stop != '$')
			return STNS_NG;
		if (v < CRYPT_ROUNDS_MIN)
			v = CRYPT_ROUNDS_MIN;
		if (v > CRYPT_ROUNDS_MAX)
			v = CRYPT_ROUNDS_MAX;
		*rounds = v;
		p = stop + 1;
	}

	*salt = p;
	if ((end = strchr(p, '$')) != NULL)
		*saltlen = (size_t)(end - p);
	else
		*saltlen = strlen(p);
	if (*saltlen > CRYPT_SALT_MAX)
		*saltlen = CRYPT_SALT_MAX;
	return STNS_OK;
}

/*
 * Is this a hash that could ever match anything?
 *
 * "*", "!", "x", "" and anything shorter than a hash are how every passwd
 * database in existence spells "this account has no password and is not to be
 * logged into".  They are refused here, before any comparison, so that a
 * locked account cannot be opened by supplying the locking string as the
 * password.
 */
static int
usable_hash(const char *hash)
{
	if (hash == NULL || *hash == '\0')
		return 0;
	if (strcmp(hash, "*") == 0 || strcmp(hash, "x") == 0)
		return 0;
	if (hash[0] == '!' || hash[0] == '*')
		return 0;
	return strlen(hash) >= 13;
}

/*
 * Check a password against a hash.
 *
 * Returns STNS_OK only for a positive match.  Every other outcome - a hash
 * this cannot verify, a malformed one, a locked account, an allocation that
 * failed - is a refusal, and the caller cannot tell them apart on purpose.
 */
/*
 * Hash a password with the scheme and salt a setting names.
 *
 * Public because a boolean is a poor thing to debug against: the tests compare
 * the string this produces with the published vector and can say how the two
 * differ, which "no" cannot.  A setting is any string beginning "$6$" or "$5$"
 * - a bare setting or a whole hash, since the part before the last field is
 * the same either way.
 */
int
stns_crypt_hash(const char *password, const char *setting, char *out, size_t outlen)
{
	const char *salt;
	size_t saltlen;
	unsigned long rounds;
	int explicit_rounds;

	if (password == NULL || setting == NULL || outlen == 0)
		return STNS_NG;
	if (strncmp(setting, "$6$", 3) != 0 && strncmp(setting, "$5$", 3) != 0)
		return STNS_NG;
	if (parse_setting(setting, &rounds, &explicit_rounds, &salt, &saltlen) != STNS_OK)
		return STNS_NG;
	if (saltlen == 0)
		return STNS_NG;

	return sha_crypt(password, salt, saltlen, rounds, explicit_rounds, setting[1] == '6', out, outlen);
}

int
stns_crypt_check(const char *password, const char *hash)
{
	char computed[256];
	int rv = STNS_NG;

	if (password == NULL || !usable_hash(hash))
		return STNS_NG;

	if (strncmp(hash, "$6$", 3) == 0 || strncmp(hash, "$5$", 3) == 0) {
		if (stns_crypt_hash(password, hash, computed, sizeof(computed)) != STNS_OK)
			return STNS_NG;
		if (strlen(computed) == strlen(hash) && stns_bcmp(computed, hash, strlen(hash)) == 0)
			rv = STNS_OK;
		stns_zero(computed, sizeof(computed));
		return rv;
	}

	/*
	 * Anything else goes to the system, which is the right answer for
	 * bcrypt on a system that has it and no answer at all elsewhere.
	 *
	 * crypt(3) on macOS does not refuse what it cannot do: handed a
	 * "$2b$..." setting it takes "$2" as a two character salt and returns
	 * a traditional DES hash, which then fails to compare - so this is
	 * safe, but it is safe by accident rather than by the system saying
	 * no, and stns_crypt_supported() below is what callers use to say
	 * something useful about it beforehand.
	 */
	{
		const char *r = crypt(password, hash);

		if (r != NULL && strlen(r) == strlen(hash) && stns_bcmp(r, hash, strlen(hash)) == 0)
			rv = STNS_OK;
	}
	return rv;
}

/*
 * Whether a hash of this shape can be checked at all on this system.
 *
 * Worth asking separately, because "wrong password" and "this machine cannot
 * read that hash" are the same answer from stns_crypt_check() and very
 * different answers to an administrator.
 */
int
stns_crypt_supported(const char *hash)
{
	if (!usable_hash(hash))
		return 0;
	if (strncmp(hash, "$6$", 3) == 0 || strncmp(hash, "$5$", 3) == 0)
		return 1;
	/*
	 * bcrypt is the system's to do, and only OpenBSD's crypt(3) does it.
	 * Everywhere else the honest answer is no - see the comment above
	 * about what macOS returns instead of an error.
	 */
	if (strncmp(hash, "$2", 2) == 0) {
#ifdef __OpenBSD__
		return 1;
#else
		return 0;
#endif
	}
	return 0;
}
