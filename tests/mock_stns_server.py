#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# A stand-in for the STNS v2 API, used by tests/integration.sh so the test
# suite does not need a Go toolchain to build the real server.
#
# It implements just the surface nss_stns talks to:
#     GET /v1/users            GET /v1/users?name=  GET /v1/users?id=
#     GET /v1/groups           GET /v1/groups?name= GET /v1/groups?id=
# plus the User-/Group-Highest-Id headers the module uses to skip lookups.
#
# The /v1 prefix is optional, because with [cached] enable = true the module
# talks to cache-stnsd's socket and the daemon is the one that knows about
# API versions.
#
# Beyond serving data it also records what it was asked, and can require
# credentials, so the tests can assert that the module really does send the
# auth_token, basic auth and http_headers it was configured with.
#
# usage: mock_stns_server.py [--auth-token T] [--basic user:pass]
#                            [--require-header K:V] [--tls CERT,KEY]
#                            [--listen ADDR] [--unix PATH | PORT]

import base64
import json
import os
import socket
import socketserver
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# Ten SSH keys for one user, nine short and one long.
#
# Ten because "the first one" and "all of them" are the same thing at one key
# and very nearly the same thing at two, and because ten of them in a single
# LDAP attribute is a SET this size has never been asked to encode.
#
# Long because the body of an ssh-rsa 4096 key is around 716 characters of
# base64, which is past every "surely a line fits in 512 bytes" anybody has
# ever written, and past the short form of a BER length as well.  It is
# synthetic and every character of it is predictable, so that a shell script
# can rebuild it and compare byte for byte.
LONG_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ" + "D" * 716 + " stnskeys@long"
MANY_KEYS = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKEY%02d stnskeys" % i for i in range(1, 10)]
MANY_KEYS.append(LONG_KEY)

USERS = [
    {
        "id": 1001,
        "name": "stnsuser",
        "group_id": 1001,
        "directory": "/home/stnsuser",
        "shell": "/bin/sh",
        "gecos": "STNS test user",
        "keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITESTKEY stnsuser"],
        "password": "",
    },
    {
        # Empty shell and directory exercise the module's defaults.
        "id": 1002,
        "name": "stnsdefault",
        "group_id": 1001,
        "directory": "",
        "shell": "",
        "gecos": "",
        "keys": [],
        "password": "",
    },
    {
        # Has a password hash, so the tests can check that it reaches root and
        # nobody else - and, since login_stns and pam_stns check a password
        # against it, a real one rather than a plausible-looking string.  It is
        # SHA-512 crypt of "correct horse battery staple" with the salt
        # "stnssalt", which "openssl passwd -6 -salt stnssalt" will reproduce.
        "id": 1004,
        "name": "stnshash",
        "group_id": 1001,
        "directory": "/home/stnshash",
        "shell": "/bin/sh",
        "gecos": "",
        "keys": [],
        "password": "$6$stnssalt$OIMtoFferfvDRURYFOfno07xGCvtuODAKpR8zK4wOUL0oRwqKXqB6kv96hFKeeb9UCZTR40OaUBzAMP.QqIgi1",
    },
    {
        # Ten keys; see MANY_KEYS above for why ten and why one of them is
        # eight hundred characters long.
        "id": 1003,
        "name": "stnskeys",
        "group_id": 1001,
        "directory": "/home/stnskeys",
        "shell": "/bin/sh",
        "gecos": "",
        "keys": MANY_KEYS,
        "password": "",
    },
]

# A group whose member list is far larger than any first-guess buffer, so that
# the ERANGE-and-retry path is exercised for real rather than only in unit
# tests.  Every member name is distinct and predictable.
BIG_MEMBERS = ["stnsbulk%03d" % i for i in range(300)]

GROUPS = [
    {"id": 1001, "name": "stnsgroup", "users": ["stnsuser", "stnsdefault"]},
    {"id": 1002, "name": "stnsops", "users": ["stnsuser"]},
    {"id": 1003, "name": "stnsempty", "users": []},
    {"id": 1004, "name": "stnsbig", "users": BIG_MEMBERS},
    # stnsuser is in this one too, so getgroupmembership has to merge three.
    {"id": 1005, "name": "stnsextra", "users": ["stnsuser"]},
]

OPTS = {"auth_token": None, "basic": None, "require_header": None}
REQUESTS = []
LOCK = threading.Lock()


def select(items, query):
    if "name" in query:
        return [i for i in items if i["name"] == query["name"][0]]
    if "id" in query:
        try:
            wanted = int(query["id"][0])
        except ValueError:
            return None
        return [i for i in items if i["id"] == wanted]
    return items


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("mock_stns: " + (fmt % args) + "\n")

    def authorized(self):
        if OPTS["auth_token"] is not None:
            if self.headers.get("Authorization") != "token " + OPTS["auth_token"]:
                return False
        if OPTS["basic"] is not None:
            want = "Basic " + base64.b64encode(OPTS["basic"].encode()).decode()
            if self.headers.get("Authorization") != want:
                return False
        if OPTS["require_header"] is not None:
            key, _, value = OPTS["require_header"].partition(":")
            if self.headers.get(key) != value:
                return False
        return True

    def do_GET(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        path = url.path
        if path.startswith("/v1"):
            path = path[3:] or "/"

        # The recording endpoint is the tests' own: never authenticated, and
        # deliberately not recorded, so that asking how many requests were made
        # does not itself count as one.
        if path == "/_requests":
            with LOCK:
                body = json.dumps(REQUESTS).encode()
            self.respond(200, body)
            return

        with LOCK:
            REQUESTS.append(
                {
                    "path": self.path,
                    "authorization": self.headers.get("Authorization"),
                    "user_agent": self.headers.get("User-Agent"),
                    "x_api_key": self.headers.get("X-Api-Key"),
                }
            )

        if not self.authorized():
            self.respond(401, b'{"error":"unauthorized"}')
            return

        if path == "/users":
            items = select(USERS, query)
        elif path == "/groups":
            items = select(GROUPS, query)
        elif path in ("/status", "/"):
            self.respond(200, b"ok", content_type="text/plain")
            return
        else:
            self.respond(404, b'{"error":"not found"}')
            return

        if items is None:
            self.respond(400, b'{"error":"bad request"}')
            return
        if not items:
            # The real server answers 404 for an empty result set, which is
            # what the module turns into a negative cache entry.
            self.respond(404, b'{"error":"not found"}')
            return

        self.respond(200, json.dumps(items).encode())

    def respond(self, code, body, content_type="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("User-Highest-Id", str(max(u["id"] for u in USERS)))
        self.send_header("User-Lowest-Id", str(min(u["id"] for u in USERS)))
        self.send_header("Group-Highest-Id", str(max(g["id"] for g in GROUPS)))
        self.send_header("Group-Lowest-Id", str(min(g["id"] for g in GROUPS)))
        self.end_headers()
        self.wfile.write(body)


class UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """Serves the same handler over a unix socket, standing in for cache-stnsd."""

    allow_reuse_address = True
    daemon_threads = True
    server_name = "unix"
    server_port = 0

    def get_request(self):
        conn, _ = super().get_request()
        # BaseHTTPRequestHandler wants a client address it can format.
        return conn, ("unix", 0)


def main():
    args = sys.argv[1:]
    unix_path = None
    tls = None
    listen = "127.0.0.1"
    port = 1104

    while args:
        arg = args.pop(0)
        if arg == "--auth-token":
            OPTS["auth_token"] = args.pop(0)
        elif arg == "--basic":
            OPTS["basic"] = args.pop(0)
        elif arg == "--require-header":
            OPTS["require_header"] = args.pop(0)
        elif arg == "--tls":
            tls = args.pop(0).split(",", 1)
        elif arg == "--listen":
            listen = args.pop(0)
        elif arg == "--unix":
            unix_path = args.pop(0)
        else:
            port = int(arg)

    if unix_path is not None:
        if os.path.exists(unix_path):
            os.unlink(unix_path)
        server = UnixHTTPServer(unix_path, Handler)
        os.chmod(unix_path, 0o666)
        sys.stderr.write("mock_stns: listening on unix:%s\n" % unix_path)
        server.serve_forever()
        return

    # An address with a colon in it is an IPv6 one, and the server class has
    # to be told: ThreadingHTTPServer is AF_INET and would try to bind "::1"
    # as though it were a name.
    if ":" in listen:
        class ThreadingHTTPServer6(ThreadingHTTPServer):
            address_family = socket.AF_INET6

        server = ThreadingHTTPServer6((listen, port), Handler)
    else:
        server = ThreadingHTTPServer((listen, port), Handler)

    # TLS, which is the whole reason this option exists.  Nothing in a client
    # that talks to 127.0.0.1 over plain HTTP touches libcurl's TLS path at
    # all - not the trust store, not the handshake, and on OpenBSD not the
    # unveil(2) that has to leave the trust store reachable.  A daemon that
    # works perfectly in a test and cannot reach an https:// endpoint on a
    # real machine is exactly the failure this stands in the way of.
    if tls is not None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=tls[0], keyfile=tls[1])
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        sys.stderr.write("mock_stns: listening on https://%s:%d\n" % (listen, port))
    else:
        sys.stderr.write("mock_stns: listening on %s:%d\n" % (listen, port))

    server.serve_forever()


if __name__ == "__main__":
    main()
