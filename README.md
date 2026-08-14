# ldapstns

[日本語](README.ja.md)

Serve an [STNS](https://stns.jp) directory to **macOS** Open Directory, over
LDAPv3 on the loopback interface.

```text
getpwnam(3) ─▶ opendirectoryd ─▶ ldap.bundle ─▶ 127.0.0.1:389 ─▶ ldapstns ─▶ STNS API
```

## Why a daemon, and why LDAP

macOS resolves users and groups through `opendirectoryd`, which is extended by
modules in `/System/Library/OpenDirectory/Modules`. Every one of them is an
Apple-signed bundle, in a directory System Integrity Protection will not let
anything be added to. Writing a module is not something that can be done
badly, or with an entitlement, or by asking nicely — it cannot be done.

What can be done is to speak a protocol one of the shipped modules already
understands. `ldap.bundle` is right there, it is well exercised, and pointing
it at `127.0.0.1` is two commands. So `ldapstns` is an LDAPv3 server that
answers out of an STNS directory.

The layout is not a design decision either. macOS maps LDAP onto its own record
types with the files in `/System/Library/OpenDirectory/Mappings`, and there are
two of them:

| | container | object classes |
| --- | --- | --- |
| `Open Directory.plist` | `cn=users`, `cn=groups` | `inetOrgPerson` + `posixAccount` + `shadowAccount` + `apple-user` + `extensibleObject`, **AND**ed |
| `RFC2307.plist` | anywhere under the suffix | `posixAccount` \| `inetOrgPerson` \| `shadowAccount`, **OR**ed |

The attribute names are identical in both — `uid`, `uidNumber`, `gidNumber`,
`cn`, `homeDirectory`, `loginShell`, `memberUid` — and only the container, the
object classes and a couple of Apple-specific attributes differ.

**Which one `dsconfigldap(8)` uses is not something it can be told.** It probes
the server and decides, and what it decides is Open Directory. That was worth
finding out the hard way: written to RFC2307 by assumption, this daemon served
users under `ou=People` while `opendirectoryd` looked under `cn=users`, and both
sides behaved exactly as designed.

So the layout served is the Open Directory one, and it satisfies both. A client
using RFC2307 searches the whole naming context for an OR of three object
classes, all three of which these entries carry; a client using Open Directory
looks under `cn=users` for all five, which they also carry. One set of entries,
either mapping, and `dsconfigldap -a 127.0.0.1` with no other argument.

The search base in both is `%!`, which means *there isn't one* —
`opendirectoryd` reads `namingContexts` from the root DSE and uses whatever it
finds. So the root DSE is not decoration; it is what makes the arrangement
configure itself.

`GeneratedUID` is served as `apple-generateduid`, in the scheme macOS uses for
its own local records: `FFFFEEEE-DDDD-CCCC-BBBB-AAAA` followed by the uid in hex
for a user, `ABCDEFAB-CDEF-ABCD-EFAB-CDEF` followed by the gid for a group. The
Open Directory mapping reads it from there; the RFC2307 one does not map it and
macOS derives the same value anyway. Either way a directory user has the same
UUID on every Mac, and the same one they would have as a local account.

## Status

| | |
| --- | --- |
| users and groups through Open Directory | yes |
| enumeration (`dscl /LDAPv3/127.0.0.1 -list /Users`) | yes |
| group membership | yes |
| SSH keys as `sshPublicKey`, and via `stns-key-wrapper` | yes |
| launchd socket activation, so the daemon never runs as root | yes |
| IPv4 and IPv6, both loopbacks by default | yes |
| `bind_dn` to close the directory to other local processes | yes |
| password authentication for `sshd`, `su` and `sudo` | yes, `pam_stns` |
| password authentication at the login window | no — see below |
| writes, StartTLS, SASL | no, deliberately |

## How it works

The daemon holds the whole directory in memory and refreshes it on a timer. A
search is answered out of that snapshot by a child process forked for the
connection.

That one decision buys most of the properties worth having. No client ever
waits on an HTTP round trip, because the refresh happens between connections.
Several clients are answered at once with no locking anywhere. And the BER
parser — the only code an untrusted peer can reach — sits in a process that
cannot modify the directory and does not outlive the connection.

If a refresh fails the previous snapshot is kept and served. An API server that
is briefly unreachable must not empty the directory out from under everybody
logged in. If the *first* refresh fails the daemon exits instead of starting:
answering "no such user" for the entire directory is worse than not running, and
launchd will try again.

## Installing

```sh
brew install --build-from-source ./pkg/homebrew/ldapstns.rb
```

or by hand — nothing but libcurl is needed, and macOS ships that:

```sh
git clone --recursive https://github.com/zakinko/ldapstns.git
cd ldapstns
make                              # Intel Homebrew, or /usr/local by hand
make PREFIX=$(brew --prefix)      # Apple Silicon
sudo make PREFIX=$(brew --prefix) install
```

`make` here is GNU make, which is what macOS ships; the `Makefile` is written to
the POSIX subset so that it does not depend on which one you have.

## Configuring

Two files, and the split is deliberate. `stns.conf` describes the API client,
is shared with `stns-key-wrapper`, and can be copied verbatim from a Linux host
or from a machine running `nss_stns`. `ldapstns.conf` is this daemon's own.

```sh
sudo mkdir -p $(brew --prefix)/etc/stns/client
sudo cp $(brew --prefix)/share/examples/ldapstns/stns.conf \
        $(brew --prefix)/etc/stns/client/stns.conf
sudo $EDITOR $(brew --prefix)/etc/stns/client/stns.conf
```

`ldapstns.conf` is optional — every setting has a working default. Check
whatever you end up with before starting anything:

```sh
ldapstns -n
```

## Starting it

`ldapstns` does not put itself into the background. On macOS, starting and
supervising a service is launchd's job, and a program that forks itself away
takes that job from it.

```sh
sudo cp $(brew --prefix)/share/ldapstns/jp.stns.ldapstns.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/jp.stns.ldapstns.plist
```

That job description uses launchd socket activation: launchd binds port 389
itself, as root, before the job starts, and hands the descriptor over. Which is
why it can name an unprivileged `UserName` and **the daemon never holds root at
all**. Started any other way — `sudo brew services start ldapstns`, or by hand
— it binds its own socket as root and then drops to the user in
`ldapstns.conf`, verifying that the change took.

Everything it has to say goes to the unified log:

```sh
log stream --predicate 'process == "ldapstns"'
```

## Pointing Open Directory at it

```sh
sudo dsconfigldap -a 127.0.0.1
```

No search base, no mapping, no schema file. Then check it, first against the
node directly and then through the search policy that everything else uses:

```sh
dscl /LDAPv3/127.0.0.1 -read /Users/alice
dscl /LDAPv3/127.0.0.1 -list /Groups
id alice
dscacheutil -q user -a name alice
```

`opendirectoryd` caches hard. After changing anything:

```sh
sudo dscacheutil -flushcache
sudo killall -HUP opendirectoryd
```

To undo all of it: `sudo dsconfigldap -r 127.0.0.1`.

## SSH keys

Unrelated to any of the above, and the part most STNS deployments actually care
about. `sshd` runs a command and reads its output, which needs nothing from
Open Directory:

```text
AuthorizedKeysCommand     /usr/local/bin/stns-key-wrapper
AuthorizedKeysCommandUser nobody
```

This is the same program `nss_stns` and `ypstns` install; it lives in
`src/stns_key_wrapper.c`, because every system can run it.

The keys are *also* served as `sshPublicKey` on each user entry, for anything
that reads them out of LDAP directly.

## What is not served, and why

**Password hashes.** `userPassword` is withheld unless `expose_password` is
set, and the daemon refuses to start if that is set without a `bind_dn`. A
loopback socket is reachable by every process on the machine; serving crypt
hashes to anonymous clients on one is a world-readable shadow file with extra
steps.

Even with a `bind_dn` it is rarely worth it. **Password authentication through
Open Directory is not the path here — `pam_stns` is**, and the split is worth
knowing before you rely on it:

| | |
| --- | --- |
| `sshd`, `su`, `sudo` | PAM, so `pam_stns` answers |
| the login window | Open Directory authentication, which asks Password Server and Kerberos — neither of which this daemon speaks |

So a directory user set up this way logs in over ssh and **not at the
keyboard**. Where the screen matters, make the account local and let STNS
supply only the keys. See `pam_stns(8)`.

The hashes are the other half of the story: macOS's `crypt(3)` reads neither
SHA-512 crypt nor bcrypt, and does not say so — handed `$6$salt$…` it takes
`$6` as a two-character salt and returns a plausible DES hash. `pam_stns`
therefore carries its own SHA-crypt, checked against published vectors.

**Writes.** Add, modify, delete, modifyDN and compare are not implemented. An
operation the daemon does not recognise gets a notice of disconnection.

**StartTLS**, and every other extended operation, refused with
`unwillingToPerform`. The daemon listens on loopback, where there is no network
for a transport to be secured against, and a half-implemented negotiation would
be worse than an honest no.

**SASL**, refused with `authMethodNotSupported`. Simple bind only.

If you want the directory closed to other local processes anyway, set `bind_dn`
and `bind_password` and give the same pair to Directory Utility under *LDAPv3 →
Edit → Use authentication when connecting*.

## Tests

```sh
make test              # BER codec, DN comparison, filter matching
make asan              # the same under AddressSanitizer and UBSan
make integration       # the real daemon, driven by ldapsearch(1)
make ident             # the sample configs' ident lines survive git archive
```

`make integration` is the one that matters. It starts the daemon against a mock
STNS server and asks **OpenLDAP's own `ldapsearch(1)`** whether what comes back
is LDAP — including with the exact filter macOS builds from `RFC2307.plist`.
Everything this daemon does is in service of being understood by a client no
test suite can stand in for, and `ldapsearch` is the closest available thing.
Nothing needs root and nothing is installed.

It also covers the things that only go wrong somewhere else: fetching the
directory over **HTTPS** with a certificate it has to verify (and refusing to
start when it cannot), the refresh timer actually firing, the API server going
away and the last good snapshot being served anyway, eight simultaneous
clients, and a user with **ten SSH keys one of which is 768 characters** —
because a key past anybody's idea of a line length is the one that comes back
truncated, and a truncated key is one person who silently cannot log in.

## Licence

BSD-2-Clause. See `LICENSE`.

## See also

| | |
| --- | --- |
| `src/stns_*.c` | the STNS API client underneath this |
| [nss_stns](https://github.com/zakinko/nss_stns) | the same thing for NetBSD, FreeBSD and DragonFly, as an `nsswitch(5)` module |
| [ypstns](https://github.com/zakinko/ypstns) | the same thing for OpenBSD, as a YP server |
