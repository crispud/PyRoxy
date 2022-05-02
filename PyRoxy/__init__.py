from contextlib import suppress
from enum import IntEnum, auto
from functools import partial
from ipaddress import ip_address
from pathlib import Path
from socket import AF_INET, SOCK_STREAM, gethostbyname
from typing import Any, AnyStr, Collection, Set

from socks import HTTP, SOCKS4, SOCKS5, socksocket
from yarl import URL

from PyRoxy.Exceptions import ProxyInvalidHost, ProxyInvalidPort, ProxyParseError
from PyRoxy.Tools import Patterns


__version__ = "1.14"
__auther__ = "MH_ProDev"
__all__ = ["ProxyUtiles", "ProxyType", "ProxySocket", "Proxy"]


class ProxyType(IntEnum):
    HTTP = auto()
    HTTPS = auto()
    SOCKS4 = auto()
    SOCKS5 = auto()

    def asPySocksType(self):
        return SOCKS5 if self == ProxyType.SOCKS5 else \
            SOCKS4 if self == ProxyType.SOCKS4 else HTTP


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
        if self.password and self.user:
            return "%s://%s:%s@%s:%d" % (self.type.name.lower(), self.user, self.password, self.host, self.port)
        else:
            return "%s://%s:%d" % (self.type.name.lower(), self.host, self.port)

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
            # Legacy ip:port:user:pass format
            username, password = None, None
            if string.replace('://', '').count(':') >= 3:
                string, username, password = string.rsplit(':', 2)

            proxy = Patterns.Proxy.search(string)
            ptype_name = proxy.group(1)
            return Proxy(
                proxy.group(4),
                int(proxy.group(5)),
                ProxyType[ptype_name.upper()] if ptype_name else ptype,
                proxy.group(2) or username,
                proxy.group(3) or password
            )

    # noinspection PyShadowingBuiltins
    def open_socket(self,
                    family=AF_INET,
                    type=SOCK_STREAM,
                    proto=-1,
                    fileno=None):
        return ProxySocket(self, family, type, proto, fileno)

    def asRequest(self):
        proxy = str(self)
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
