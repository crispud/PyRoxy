from base64 import b64encode
from contextlib import suppress
from enum import IntEnum, auto
from functools import partial
from ipaddress import ip_address
from pathlib import Path
from socket import AF_INET, SOCK_STREAM, gethostbyname, socket
from typing import Any, AnyStr, Collection, Set

from socks import GeneralProxyError, HTTP, HTTPError, SOCKS4, SOCKS5, socksocket
from yarl import URL

from PyRoxy.Exceptions import ProxyInvalidHost, ProxyInvalidPort, ProxyParseError
from PyRoxy.Tools import Patterns


__version__ = "1.1"
__auther__ = "MH_ProDev"
__all__ = ["ProxyUtiles", "ProxyType", "ProxySocket", "Proxy"]


class ProxyType(IntEnum):
    HTTP = auto()
    HTTPS = auto()
    SOCKS4 = auto()
    SOCKS5 = auto()

    def asPySocksType(self):
        return SOCKS5 if self == ProxyType.SOCKS5 else \
            SOCKS4 if self == ProxyType.SOCKS4 else \
                HTTP


class Proxy(object):
    user: Any
    password: Any
    port: int
    type: ProxyType
    host: AnyStr

    def __init__(
        self,
        host: str,
        port: int = 0,
        proxy_type: ProxyType = ProxyType.HTTP,
        user=None,
        password=None
    ):
        if proxy_type == ProxyType.HTTPS:
            proxy_type = ProxyType.HTTP
        try:
            host = str(ip_address(host))
        except ValueError:
            host = gethostbyname(host)
        port = int(port)
        assert 1 <= port <= 65535
        self.host = host
        self.type = proxy_type
        self.port = port
        self.user = user or None
        self.password = password or None

    def __str__(self):
        return "%s://%s:%d%s" % (self.type.name.lower(), self.host, self.port,
                                 (":%s:%s" % (self.user, self.password)
                                  if self.password and self.user else ""))

    def __repr__(self):
        return "<%s Proxy %s:%d>" % (self.type.name, self.host, self.port)

    def as_tuple(self):
        return self.host, self.port, self.type, self.user, self.password

    def __eq__(self, other):
        return self.as_tuple() == other.as_tuple()

    def __hash__(self):
        return hash(self.as_tuple())

    @staticmethod
    def fromString(string: str, ptype=ProxyType.HTTP):
        with suppress(Exception):
            if '@' in string:
                auth, ip_port = string.split('@', 1)
                if '://' in auth:
                    _, auth = auth.split('://', 1)
                string = string.replace(auth + '@', '') + ':' + auth

            proxy: Any = Patterns.Proxy.search(string)
            ptype_name = proxy.group(1)
            return Proxy(
                proxy.group(2),
                int(proxy.group(3))
                if proxy.group(3) and proxy.group(3).isdigit() else 80,
                ProxyType[ptype_name.upper()] if ptype_name else ptype,
                proxy.group(4),
                proxy.group(5)
            )
        return None

    def ip_port(self):
        return "%s:%d" % (self.host, self.port)

    @staticmethod
    def validate(host: str, port: int):
        with suppress(ValueError):
            if not ip_address(host):
                raise ProxyInvalidHost(host)
            if not Patterns.Port.match(str(port)):
                raise ProxyInvalidPort(port)
            return True
        raise ProxyInvalidHost(host)

    # noinspection PyShadowingBuiltins
    def open_socket(self,
                    family=AF_INET,
                    type=SOCK_STREAM,
                    proto=-1,
                    fileno=None):
        return ProxySocket(self, family, type, proto, fileno)

    def wrap(self, sock: Any):
        if isinstance(sock, socket):
            return self.open_socket(sock.family, sock.type, sock.proto, sock.fileno())
        sock.proxies = self.asRequest()
        return sock

    def asRequest(self):
        if self.password and self.user:
            proxy = "%s://%s:%s@%s:%d" % (self.type.name.lower(), self.user, self.password, self.host, self.port)
        else:
            proxy = "%s://%s:%d" % (self.type.name.lower(), self.host, self.port)

        return {"http": proxy, "https": proxy}

    # noinspection PyUnreachableCode
    def check(self, url: Any = "https://httpbin.org/get", timeout=5):
        if not isinstance(url, URL): url = URL(url)
        with suppress(Exception):
            with self.open_socket() as sock:
                sock.settimeout(timeout)
                sock.connect((url.host, url.port or 80))
                return True
        return False


# noinspection PyShadowingBuiltins
class ProxySocket(socksocket):

    def __init__(self,
                 proxy: Proxy,
                 family=-1,
                 type=-1,
                 proto=-1,
                 fileno=None):
        super().__init__(family, type, proto, fileno)
        if proxy.port:
            if proxy.user and proxy.password:
                self.setproxy(proxy.type.asPySocksType(),
                              proxy.host,
                              proxy.port,
                              username=proxy.user,
                              password=proxy.password)
                return
            self.setproxy(proxy.type.asPySocksType(), proxy.host, proxy.port)
            return
        if proxy.user and proxy.password:
            self.setproxy(proxy.type.asPySocksType(),
                          proxy.host,
                          username=proxy.user,
                          password=proxy.password)
            return
        self.setproxy(proxy.type.asPySocksType(), proxy.host)

    def _negotiate_HTTP(self, dest_addr, dest_port):
        proxy_type, addr, port, rdns, username, password = self.proxy

        # If we need to resolve locally, we do this now
        addr = dest_addr if rdns else socket.gethostbyname(dest_addr)

        http_headers = [
            (b"CONNECT " + addr.encode("idna") + b":"
             + str(dest_port).encode() + b" HTTP/1.1"),
            b"Host: " + dest_addr.encode("idna")
        ]

        if username and password:
            http_headers.append(b"Proxy-Authorization: basic "
                                + b64encode(username + b":" + password))

        http_headers.append(b"\r\n")

        self.sendall(b"\r\n".join(http_headers))

        resp = b''
        while True:
            data = self.recv(1024)
            if not data:
                break
            resp += data
            if len(resp) > 64 or b'\r\n\r\n' in resp:
                break

        if not resp:
            raise GeneralProxyError("Connection closed unexpectedly")

        status_line, *other = resp.decode().splitlines()

        if any(other):
            raise GeneralProxyError("Proxy server does not appear to be an HTTP proxy")

        try:
            proto, status_code, status_msg = status_line.split(" ", 2)
        except ValueError:
            raise GeneralProxyError("HTTP proxy server sent invalid response")

        if not proto.startswith("HTTP/"):
            raise GeneralProxyError(
                "Proxy server does not appear to be an HTTP proxy")

        try:
            status_code = int(status_code)
        except ValueError:
            raise HTTPError(
                "HTTP proxy server did not return a valid HTTP status")

        if status_code != 200:
            error = "{}: {}".format(status_code, status_msg)
            if status_code in (400, 403, 405):
                # It's likely that the HTTP proxy server does not support the
                # CONNECT tunneling method
                error += ("\n[*] Note: The HTTP proxy server may not be"
                          " supported by PySocks (must be a CONNECT tunnel"
                          " proxy)")
            raise HTTPError(error)

        self.proxy_sockname = (b"0.0.0.0", 0)
        self.proxy_peername = addr, dest_port


ProxySocket._proxy_negotiators[HTTP] = ProxySocket._negotiate_HTTP


class ProxyUtiles:
    @staticmethod
    def parseAll(proxies: Collection[str],
                 ptype: ProxyType = ProxyType.HTTP) -> Set[Proxy]:
        res = set(map(partial(Proxy.fromString, ptype=ptype), proxies))
        while None in res:
            res.remove(None)
        return res

    @staticmethod
    def readFromFile(path: Any, ptype: ProxyType = ProxyType.HTTP) -> Set[Proxy]:
        if isinstance(path, Path):
            with path.open("r+") as read:
                lines = read.readlines()
        else:
            with open(path, "r+") as read:
                lines = read.readlines()

        return ProxyUtiles.parseAll([prox.strip() for prox in lines], ptype)
