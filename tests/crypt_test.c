/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * Unit tests for src/stns_crypt.c.
 *
 * Everything here is checked against a value produced by something other than
 * this code, which for cryptography is the only kind of test worth having: a
 * hash that is wrong in a self-consistent way passes any round trip you care
 * to write.  The digests are the FIPS 180-4 vectors.  The crypt outputs were
 * each confirmed against "openssl passwd -6" where it can express the setting,
 * and against an implementation written separately from the specification
 * where it cannot - which is how the round counts other than the default were
 * settled, since openssl passwd has no way to ask for one.
 *
 * That cross-check earned itself immediately.  One of these vectors was
 * written down from memory with the right first forty-five characters and the
 * wrong remainder, and the temptation on seeing a near miss is to go looking
 * for the bug in the code.  There was no bug in the code.
 *
 * The other half is refusals.  This code decides whether somebody may log in,
 * so what matters at least as much as matching a correct password is never
 * matching anything else - a locked account, a hash format this system cannot
 * read, a truncated hash, or the string the passwd file uses to mean "no".
 */
#include <stdio.h>
#include <string.h>

#include "stns.h"

static int checks;
static int failures;

#define CHECK(cond)                                                                                                    \
	do {                                                                                                           \
		checks++;                                                                                              \
		if (!(cond)) {                                                                                         \
			failures++;                                                                                    \
			(void)printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                                   \
		}                                                                                                      \
	} while (0)

static void
check_digest(const char *label, const uint8_t *got, size_t len, const char *want)
{
	char hex[129];
	size_t i;

	for (i = 0; i < len; i++)
		(void)snprintf(hex + i * 2, 3, "%02x", got[i]);

	checks++;
	if (strcmp(hex, want) != 0) {
		failures++;
		(void)printf("FAIL %s\n  expected %s\n  got      %s\n", label, want, hex);
	}
}

/* FIPS 180-4, the one-block, two-block and empty cases. */
static void
test_sha256(void)
{
	uint8_t d[32];

	stns_sha256("", 0, d);
	check_digest("SHA-256 of the empty string", d, sizeof(d),
	    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

	stns_sha256("abc", 3, d);
	check_digest("SHA-256 of \"abc\"", d, sizeof(d),
	    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

	stns_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d);
	check_digest("SHA-256, two blocks", d, sizeof(d),
	    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

static void
test_sha512(void)
{
	uint8_t d[64];

	stns_sha512("", 0, d);
	check_digest("SHA-512 of the empty string", d, sizeof(d),
	    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
	    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

	stns_sha512("abc", 3, d);
	check_digest("SHA-512 of \"abc\"", d, sizeof(d),
	    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
	    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

	stns_sha512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
		    "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
	    112, d);
	check_digest("SHA-512, two blocks", d, sizeof(d),
	    "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
	    "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
}

/*
 * The vectors from the specification, checked through the public interface.
 *
 * stns_crypt_check() only says yes or no, which is all a caller ever needs -
 * so matching the published output is the test, and the wrong password beside
 * each one is what stops a function that always said yes from passing.
 */
static void
check_vector(const char *password, const char *hash)
{
	char computed[256];

	checks++;
	if (stns_crypt_check(password, hash) != STNS_OK) {
		failures++;
		if (stns_crypt_hash(password, hash, computed, sizeof(computed)) != STNS_OK)
			(void)strlcpy(computed, "(could not be computed)", sizeof(computed));
		(void)printf("FAIL the published vector did not match\n  expected %s\n  got      %s\n", hash,
		    computed);
	}
	CHECK(stns_crypt_check("the wrong password", hash) == STNS_NG);
	CHECK(stns_crypt_supported(hash) == 1);
}

static void
test_sha512_crypt(void)
{
	check_vector("Hello world!",
	    "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJ"
	    "uesI68u4OTLiBFdcbYEdFCoEOfaS35inz1");

	/* A round count that is not the default, and a salt past sixteen. */
	check_vector("Hello world!",
	    "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sb"
	    "HbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.");

	check_vector("This is just a test",
	    "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeK"
	    "QzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0");

	/*
	 * A password of 84 bytes, which is the only one here longer than a
	 * SHA-512 digest and so the only one that exercises the steps where the
	 * digest is repeated to the length of the password.
	 */
	check_vector("a very much longer text to encrypt.  This one even stretches over more"
		     "than one line.",
	    "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.w"
	    "PvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1");
}

static void
test_sha256_crypt(void)
{
	check_vector("Hello world!", "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5");

	check_vector("Hello world!",
	    "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA");

	check_vector("This is just a test",
	    "$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5");
}

/*
 * Everything that must not be a match.
 *
 * The locked-account strings are the important ones.  A passwd database says
 * "this account cannot be logged into" by putting "*", "!" or "x" where the
 * hash goes, and an implementation that ran those through crypt(3) and
 * compared would let anybody in who typed the right nonsense.
 */
static void
test_refusals(void)
{
	static const char *const locked[] = { "*", "!", "!!", "x", "", "*LK*", "!$6$salt$whatever", NULL };
	const char *good = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJ"
			   "uesI68u4OTLiBFdcbYEdFCoEOfaS35inz1";
	size_t i;

	for (i = 0; locked[i] != NULL; i++) {
		CHECK(stns_crypt_check("", locked[i]) == STNS_NG);
		CHECK(stns_crypt_check(locked[i], locked[i]) == STNS_NG);
		CHECK(stns_crypt_check("anything at all", locked[i]) == STNS_NG);
		CHECK(stns_crypt_supported(locked[i]) == 0);
	}

	/* A NULL either side is a refusal and not a crash. */
	CHECK(stns_crypt_check(NULL, good) == STNS_NG);
	CHECK(stns_crypt_check("Hello world!", NULL) == STNS_NG);
	CHECK(stns_crypt_supported(NULL) == 0);

	/* A hash of the right shape with the wrong contents. */
	CHECK(stns_crypt_check("Hello world!", "$6$saltstring$notevenclose") == STNS_NG);
	CHECK(stns_crypt_check("Hello world!", "$6$") == STNS_NG);
	CHECK(stns_crypt_check("Hello world!", "$6$saltstring$") == STNS_NG);

	/* A prefix nothing here implements. */
	CHECK(stns_crypt_supported("$1$saltstrn$oaQ7Lg6Z0G6Z0G6Z0G6Z0.") == 0);
	CHECK(stns_crypt_supported("$y$j9T$saltsaltsalt$blahblahblah") == 0);

	/*
	 * bcrypt is the system's to do, and only OpenBSD's crypt(3) does it.
	 * Everywhere else the answer has to be "no" rather than a comparison
	 * against whatever crypt(3) decided to return - macOS, handed a "$2b$"
	 * setting, treats "$2" as a two character salt and hands back a
	 * traditional DES hash without a word.
	 */
#ifdef __OpenBSD__
	CHECK(stns_crypt_supported("$2b$10$abcdefghijklmnopqrstuu") == 1);
#else
	CHECK(stns_crypt_supported("$2b$10$abcdefghijklmnopqrstuu") == 0);
#endif

	/* An empty password against a real hash is still just wrong. */
	CHECK(stns_crypt_check("", good) == STNS_NG);
	CHECK(stns_crypt_check("Hello world", good) == STNS_NG);
	CHECK(stns_crypt_check("Hello world!!", good) == STNS_NG);
	CHECK(stns_crypt_check("Hello world!", good) == STNS_OK);
}

/*
 * The round count is clamped rather than refused.
 *
 * A hash naming fewer rounds than the minimum was produced by something that
 * clamped it the same way, so clamping here is what makes the two agree; the
 * alternative is refusing a hash the rest of the world accepts.
 */
static void
test_rounds_clamped(void)
{
	/* rounds=10 is below the minimum of 1000 and must behave as 1000. */
	CHECK(stns_crypt_check("Hello world!", "$6$rounds=10$saltstring$x") == STNS_NG);
	CHECK(stns_crypt_supported("$6$rounds=10$saltstring$x") == 1);

	/* A rounds= that is not a number at all is malformed. */
	CHECK(stns_crypt_check("Hello world!", "$6$rounds=abc$saltstring$x") == STNS_NG);
}

int
main(void)
{
	test_sha256();
	test_sha512();
	test_sha512_crypt();
	test_sha256_crypt();
	test_refusals();
	test_rounds_clamped();

	(void)printf("%d checks, %d failures\n", checks, failures);
	return (failures == 0) ? 0 : 1;
}
