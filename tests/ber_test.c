/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zakinko
 *
 * Unit tests for the parts of the daemon that need neither a socket nor a
 * server: the BER codec, distinguished name comparison, and filter matching.
 *
 * Roughly half of these are tests that something is *refused*.  The decoder is
 * the only code in this program an unauthenticated client can reach, and what
 * matters about it is not the messages it parses - tests/integration.sh proves
 * those, against a real LDAP client - but the ones it declines to.
 */
#include <errno.h>

#include "ldapstns.h"

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

#define CHECK_STR(got, want)                                                                                           \
	do {                                                                                                           \
		checks++;                                                                                              \
		if ((got) == NULL || strcmp((got), (want)) != 0) {                                                     \
			failures++;                                                                                    \
			(void)printf("FAIL %s:%d: expected \"%s\", got \"%s\"\n", __FILE__, __LINE__, (want),          \
			    ((got) != NULL) ? (got) : "(null)");                                                       \
		}                                                                                                      \
	} while (0)

/* Does encoding this integer produce exactly these bytes? */
static void
check_int(long v, const char *want, size_t wantlen)
{
	bbuf b;

	bbuf_init(&b);
	bbuf_int(&b, BER_INTEGER, v);
	checks++;
	if (b.error || b.len != wantlen || memcmp(b.p, want, wantlen) != 0) {
		size_t i;

		failures++;
		(void)printf("FAIL encoding %ld: got", v);
		for (i = 0; i < b.len; i++)
			(void)printf(" %02x", b.p[i]);
		(void)printf(", wanted");
		for (i = 0; i < wantlen; i++)
			(void)printf(" %02x", (unsigned char)want[i]);
		(void)printf("\n");
	}
	bbuf_free(&b);
}

/*
 * A BER integer carries its sign in its first bit, so the encoding is not
 * simply "the value in as few bytes as possible": 128 needs a leading zero
 * byte that 127 does not, or it would read back as -128.
 */
static void
test_encode_int(void)
{
	check_int(0, "\x02\x01\x00", 3);
	check_int(1, "\x02\x01\x01", 3);
	check_int(127, "\x02\x01\x7f", 3);
	check_int(128, "\x02\x02\x00\x80", 4);
	check_int(255, "\x02\x02\x00\xff", 4);
	check_int(256, "\x02\x02\x01\x00", 4);
	check_int(-1, "\x02\x01\xff", 3);
	check_int(-128, "\x02\x01\x80", 3);
	check_int(-129, "\x02\x02\xff\x7f", 4);
}

/* Below 128 bytes a length is one byte; at 128 it grows a length-of-length. */
static void
test_encode_length(void)
{
	char big[300];
	bbuf b;

	memset(big, 'x', sizeof(big));

	bbuf_init(&b);
	bbuf_tlv(&b, BER_OCTETSTRING, big, 127);
	CHECK(!b.error && b.len == 129 && b.p[0] == 0x04 && b.p[1] == 127);
	bbuf_free(&b);

	bbuf_init(&b);
	bbuf_tlv(&b, BER_OCTETSTRING, big, 128);
	CHECK(!b.error && b.len == 131 && b.p[1] == 0x81 && b.p[2] == 128);
	bbuf_free(&b);

	bbuf_init(&b);
	bbuf_tlv(&b, BER_OCTETSTRING, big, 300);
	CHECK(!b.error && b.len == 304 && b.p[1] == 0x82 && b.p[2] == 0x01 && b.p[3] == 0x2c);
	bbuf_free(&b);
}

static void
test_roundtrip(void)
{
	bbuf inner, outer;
	ber b, seq;
	char *s = NULL;
	long v;
	int flag;

	bbuf_init(&inner);
	bbuf_init(&outer);
	bbuf_int(&inner, BER_INTEGER, 42);
	bbuf_str(&inner, BER_OCTETSTRING, "hello");
	bbuf_bool(&inner, BER_BOOLEAN, 1);
	bbuf_wrap(&outer, BER_SEQUENCE, &inner);
	CHECK(!outer.error);

	ber_init(&b, outer.p, outer.len);
	CHECK(ber_expect(&b, BER_SEQUENCE, &seq));
	CHECK(ber_int(&seq, BER_INTEGER, &v) && v == 42);
	CHECK(ber_str(&seq, BER_OCTETSTRING, &s));
	CHECK_STR(s, "hello");
	CHECK(ber_bool(&seq, BER_BOOLEAN, &flag) && flag == 1);
	CHECK(ber_end(&seq));

	free(s);
	bbuf_free(&inner);
	bbuf_free(&outer);
}

/*
 * A failed read must leave the cursor where it was, or a caller that tries one
 * tag and then another - which is how every CHOICE in the protocol is parsed -
 * would be looking at different bytes the second time.
 */
static void
test_failed_read_does_not_advance(void)
{
	const uint8_t msg[] = { 0x02, 0x01, 0x2a };
	ber b;
	char *s = NULL;
	long v;

	ber_init(&b, msg, sizeof(msg));
	CHECK(!ber_str(&b, BER_OCTETSTRING, &s));
	CHECK(b.pos == 0);
	CHECK(ber_int(&b, BER_INTEGER, &v) && v == 42);
}

static void
test_decoder_refusals(void)
{
	ber b;
	char *s = NULL;
	uint8_t tag;

	/* A length that runs off the end of the buffer. */
	{
		const uint8_t msg[] = { 0x04, 0x10, 'a', 'b' };

		ber_init(&b, msg, sizeof(msg));
		CHECK(!ber_tlv(&b, &tag, NULL));
	}

	/*
	 * The indefinite length form: 0x80, terminated by two zero bytes
	 * somewhere further on.  Accepting it would mean scanning ahead through
	 * bytes that have not been validated to find out where the value ends.
	 */
	{
		const uint8_t msg[] = { 0x30, 0x80, 0x00, 0x00 };

		ber_init(&b, msg, sizeof(msg));
		CHECK(!ber_tlv(&b, &tag, NULL));
	}

	/* A multi byte tag, which LDAP has no use for. */
	{
		const uint8_t msg[] = { 0x1f, 0x81, 0x00, 0x01 };

		ber_init(&b, msg, sizeof(msg));
		CHECK(!ber_tlv(&b, &tag, NULL));
	}

	/* A length field wider than a size_t. */
	{
		const uint8_t msg[] = { 0x04, 0x89, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		ber_init(&b, msg, sizeof(msg));
		CHECK(!ber_tlv(&b, &tag, NULL));
	}

	/* Nothing at all, and half a header. */
	{
		const uint8_t msg[] = { 0x04 };

		ber_init(&b, msg, 0);
		CHECK(!ber_tlv(&b, &tag, NULL));
		ber_init(&b, msg, 1);
		CHECK(!ber_tlv(&b, &tag, NULL));
	}

	/*
	 * An octet string with a NUL in it.  Truncating at the NUL is how a
	 * value comes to match something it does not say it matches.
	 */
	{
		const uint8_t msg[] = { 0x04, 0x05, 'a', 'b', 0x00, 'c', 'd' };

		ber_init(&b, msg, sizeof(msg));
		CHECK(!ber_str(&b, BER_OCTETSTRING, &s));
	}

	/* An integer with no bytes, and one too wide to hold. */
	{
		const uint8_t empty[] = { 0x02, 0x00 };
		const uint8_t wide[] = { 0x02, 0x09, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		long v;

		ber_init(&b, empty, sizeof(empty));
		CHECK(!ber_int(&b, BER_INTEGER, &v));
		ber_init(&b, wide, sizeof(wide));
		CHECK(!ber_int(&b, BER_INTEGER, &v));
	}
}

static void
test_dn_normalise(void)
{
	char *s;

	s = dn_normalise("UID=Alice,CN=Users,DC=stns");
	CHECK_STR(s, "uid=alice,cn=users,dc=stns");
	free(s);

	s = dn_normalise("cn=users, dc=stns");
	CHECK_STR(s, "cn=users,dc=stns");
	free(s);

	s = dn_normalise("  cn = users ,  dc = stns  ");
	CHECK_STR(s, "cn=users,dc=stns");
	free(s);

	/* Space inside a value is significant and has to survive. */
	s = dn_normalise("cn=John Smith,dc=stns");
	CHECK_STR(s, "cn=john smith,dc=stns");
	free(s);

	s = dn_normalise("");
	CHECK_STR(s, "");
	free(s);
}

static void
test_dn_scope(void)
{
	CHECK(dn_in_subtree("dc=stns", "dc=stns"));
	CHECK(dn_in_subtree("cn=users,dc=stns", "dc=stns"));
	CHECK(dn_in_subtree("uid=a,cn=users,dc=stns", "dc=stns"));
	CHECK(!dn_in_subtree("dc=stns", "cn=users,dc=stns"));
	/* "dc=notstns" must not look like a child of "dc=stns". */
	CHECK(!dn_in_subtree("dc=notstns", "dc=stns"));
	CHECK(!dn_in_subtree("uid=a,cn=users,dc=other", "dc=stns"));
	/* Everything is under the empty base. */
	CHECK(dn_in_subtree("dc=stns", ""));

	CHECK(dn_is_child_of("cn=users,dc=stns", "dc=stns"));
	CHECK(!dn_is_child_of("uid=a,cn=users,dc=stns", "dc=stns"));
	CHECK(!dn_is_child_of("dc=stns", "dc=stns"));
	/* The suffix is a child of the root; nothing deeper is. */
	CHECK(dn_is_child_of("dc=stns", ""));
	CHECK(!dn_is_child_of("cn=users,dc=stns", ""));
}

static void
test_entry(void)
{
	const ldap_attr *a;
	ldap_entry e;

	CHECK(entry_init(&e, "uid=Alice,dc=stns") == 0);
	CHECK_STR(e.dn, "uid=Alice,dc=stns");
	CHECK_STR(e.ndn, "uid=alice,dc=stns");

	CHECK(entry_add(&e, "objectClass", "top") == 0);
	CHECK(entry_add(&e, "objectClass", "posixAccount") == 0);
	CHECK(entry_addf(&e, "uidNumber", "%d", 1001) == 0);

	/* Repeating a name appends to the one attribute, it does not add a second. */
	CHECK(e.nattrs == 2);
	a = entry_find(&e, "objectclass");
	CHECK(a != NULL && a->nvals == 2);
	CHECK_STR(a->vals[1], "posixAccount");
	a = entry_find(&e, "UIDNUMBER");
	CHECK(a != NULL && a->nvals == 1);
	CHECK_STR(a->vals[0], "1001");
	CHECK(entry_find(&e, "loginShell") == NULL);

	entry_free_contents(&e);
	CHECK(e.nattrs == 0 && e.dn == NULL);
}

/*
 * Filters are built as BER and then parsed back, rather than being constructed
 * directly, so that what is tested is the same path a client's message takes.
 */
static void
put_ava(bbuf *out, uint8_t tag, const char *attr, const char *value)
{
	bbuf in;

	bbuf_init(&in);
	bbuf_str(&in, BER_OCTETSTRING, attr);
	bbuf_str(&in, BER_OCTETSTRING, value);
	bbuf_wrap(out, tag, &in);
	bbuf_free(&in);
}

static ldap_filter *
parse_buf(bbuf *b)
{
	ber cursor;

	ber_init(&cursor, b->p, b->len);
	return filter_parse(&cursor);
}

static void
test_filter(void)
{
	ldap_filter *f;
	ldap_entry e;
	bbuf b, inner, sub, parts;

	CHECK(entry_init(&e, "uid=alice,cn=users,dc=stns") == 0);
	(void)entry_add(&e, "objectClass", "posixAccount");
	(void)entry_add(&e, "uid", "alice");
	(void)entry_add(&e, "uidNumber", "1001");
	(void)entry_add(&e, "cn", "Alice Liddell");

	/* (uid=alice), and the same asked for in the wrong case. */
	bbuf_init(&b);
	put_ava(&b, LDAP_FILT_EQUALITY, "uid", "alice");
	CHECK((f = parse_buf(&b)) != NULL && filter_match(f, &e));
	filter_free(f);
	bbuf_free(&b);

	bbuf_init(&b);
	put_ava(&b, LDAP_FILT_EQUALITY, "UID", "ALICE");
	CHECK((f = parse_buf(&b)) != NULL && filter_match(f, &e));
	filter_free(f);
	bbuf_free(&b);

	bbuf_init(&b);
	put_ava(&b, LDAP_FILT_EQUALITY, "uid", "bob");
	CHECK((f = parse_buf(&b)) != NULL && !filter_match(f, &e));
	filter_free(f);
	bbuf_free(&b);

	/* An attribute the entry does not have simply does not match. */
	bbuf_init(&b);
	put_ava(&b, LDAP_FILT_EQUALITY, "loginShell", "/bin/sh");
	CHECK((f = parse_buf(&b)) != NULL && !filter_match(f, &e));
	filter_free(f);
	bbuf_free(&b);

	/* (uid=*) and (loginShell=*) */
	bbuf_init(&b);
	bbuf_str(&b, LDAP_FILT_PRESENT, "uid");
	CHECK((f = parse_buf(&b)) != NULL && filter_match(f, &e));
	filter_free(f);
	bbuf_free(&b);

	bbuf_init(&b);
	bbuf_str(&b, LDAP_FILT_PRESENT, "loginShell");
	CHECK((f = parse_buf(&b)) != NULL && !filter_match(f, &e));
	filter_free(f);
	bbuf_free(&b);

	/* (&(objectClass=posixAccount)(uid=alice)) */
	bbuf_init(&b);
	bbuf_init(&inner);
	put_ava(&inner, LDAP_FILT_EQUALITY, "objectClass", "posixAccount");
	put_ava(&inner, LDAP_FILT_EQUALITY, "uid", "alice");
	bbuf_wrap(&b, LDAP_FILT_AND, &inner);
	CHECK((f = parse_buf(&b)) != NULL && filter_match(f, &e));
	filter_free(f);
	bbuf_free(&inner);
	bbuf_free(&b);

	/* (|(uid=bob)(uid=alice)) */
	bbuf_init(&b);
	bbuf_init(&inner);
	put_ava(&inner, LDAP_FILT_EQUALITY, "uid", "bob");
	put_ava(&inner, LDAP_FILT_EQUALITY, "uid", "alice");
	bbuf_wrap(&b, LDAP_FILT_OR, &inner);
	CHECK((f = parse_buf(&b)) != NULL && filter_match(f, &e));
	filter_free(f);
	bbuf_free(&inner);
	bbuf_free(&b);

	/* (!(uid=bob)) */
	bbuf_init(&b);
	bbuf_init(&inner);
	put_ava(&inner, LDAP_FILT_EQUALITY, "uid", "bob");
	bbuf_wrap(&b, LDAP_FILT_NOT, &inner);
	CHECK((f = parse_buf(&b)) != NULL && filter_match(f, &e));
	filter_free(f);
	bbuf_free(&inner);
	bbuf_free(&b);

	/* (cn=Alice*Liddell) */
	bbuf_init(&b);
	bbuf_init(&inner);
	bbuf_init(&parts);
	bbuf_str(&parts, LDAP_SUB_INITIAL, "alice");
	bbuf_str(&parts, LDAP_SUB_FINAL, "liddell");
	bbuf_str(&inner, BER_OCTETSTRING, "cn");
	bbuf_wrap(&inner, BER_SEQUENCE, &parts);
	bbuf_wrap(&b, LDAP_FILT_SUBSTRINGS, &inner);
	CHECK((f = parse_buf(&b)) != NULL && filter_match(f, &e));
	filter_free(f);
	bbuf_free(&parts);
	bbuf_free(&inner);
	bbuf_free(&b);

	/* (cn=*zzz*) */
	bbuf_init(&b);
	bbuf_init(&inner);
	bbuf_init(&parts);
	bbuf_str(&parts, LDAP_SUB_ANY, "zzz");
	bbuf_str(&inner, BER_OCTETSTRING, "cn");
	bbuf_wrap(&inner, BER_SEQUENCE, &parts);
	bbuf_wrap(&b, LDAP_FILT_SUBSTRINGS, &inner);
	CHECK((f = parse_buf(&b)) != NULL && !filter_match(f, &e));
	filter_free(f);
	bbuf_free(&parts);
	bbuf_free(&inner);
	bbuf_free(&b);

	/*
	 * (uidNumber>=999).  Compared as text, "1001" sorts before "999" and
	 * this answers the opposite of what was asked.
	 */
	bbuf_init(&b);
	put_ava(&b, LDAP_FILT_GE, "uidNumber", "999");
	CHECK((f = parse_buf(&b)) != NULL && filter_match(f, &e));
	filter_free(f);
	bbuf_free(&b);

	bbuf_init(&b);
	put_ava(&b, LDAP_FILT_LE, "uidNumber", "999");
	CHECK((f = parse_buf(&b)) != NULL && !filter_match(f, &e));
	filter_free(f);
	bbuf_free(&b);

	/* A substring filter with no substrings in it is malformed. */
	bbuf_init(&b);
	bbuf_init(&inner);
	bbuf_init(&parts);
	bbuf_str(&inner, BER_OCTETSTRING, "cn");
	bbuf_wrap(&inner, BER_SEQUENCE, &parts);
	bbuf_wrap(&b, LDAP_FILT_SUBSTRINGS, &inner);
	CHECK(parse_buf(&b) == NULL);
	bbuf_free(&parts);
	bbuf_free(&inner);
	bbuf_free(&b);

	/* An extensibleMatch is not implemented and must be refused, not ignored. */
	bbuf_init(&b);
	bbuf_init(&sub);
	bbuf_str(&sub, BER_OCTETSTRING, "x");
	bbuf_wrap(&b, BER_CONTEXT | BER_CONSTRUCTED | 9, &sub);
	CHECK(parse_buf(&b) == NULL);
	bbuf_free(&sub);
	bbuf_free(&b);

	entry_free_contents(&e);
}

/*
 * A filter nested past the depth limit is refused rather than recursed into.
 * Forty nested "not"s is nothing for a client to generate and quite enough to
 * matter if the recursion were unbounded.
 */
static void
test_filter_depth(void)
{
	bbuf layers[2];
	int i, cur = 0;

	bbuf_init(&layers[0]);
	bbuf_init(&layers[1]);
	bbuf_str(&layers[0], LDAP_FILT_PRESENT, "uid");

	for (i = 0; i < 40; i++) {
		int next = 1 - cur;

		bbuf_free(&layers[next]);
		bbuf_init(&layers[next]);
		bbuf_wrap(&layers[next], LDAP_FILT_NOT, &layers[cur]);
		cur = next;
	}

	CHECK(parse_buf(&layers[cur]) == NULL);
	bbuf_free(&layers[0]);
	bbuf_free(&layers[1]);
}

int
main(void)
{
	test_encode_int();
	test_encode_length();
	test_roundtrip();
	test_failed_read_does_not_advance();
	test_decoder_refusals();
	test_dn_normalise();
	test_dn_scope();
	test_entry();
	test_filter();
	test_filter_depth();

	(void)printf("%d checks, %d failures\n", checks, failures);
	return (failures == 0) ? 0 : 1;
}
