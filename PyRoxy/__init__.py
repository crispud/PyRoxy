from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from enum import IntEnum, auto
from functools import partial
from ipaddress import ip_address
from multiprocessing import cpu_count
from pathlib import Path
from socket import socket, SOCK_STREAM, AF_INET, gethostbyname
from typing import AnyStr, Set, Collection, Any

from socks import socksocket, SOCKS4, SOCKS5, HTTP
from yarl import URL

from PyRoxy.Exceptions import ProxyInvalidHost, ProxyInvalidPort, ProxyParseError
from PyRoxy.Tools import Patterns

__version__ = "1.1"
__auther__ = "MH_ProDev"
__all__ = ["ProxyUtiles", "ProxyType", "ProxySocket", "ProxyChecker", "Proxy"]


class ProxyType(IntEnum):
    HTTP = auto()
    HTTPS = auto()
    SOCKS4 = auto()
    SOCKS5 = auto()

    def asPySocksType(self):
        return SOCKS5 if self == ProxyType.SOCKS5 else \
            SOCKS4 if self == ProxyType.SOCKS4 else \
                HTTP

    @staticmethod
    def stringToProxyType(n: str):
        return (ProxyType.SOCKS5 if n.lower() == "socks5" else
                ProxyType.SOCKS4 if n.lower() == "socks4" else ProxyType.HTTP
                ) if not (n.isdigit()) else (
                    ProxyType.SOCKS5 if int(n) == 5 else
                    ProxyType.SOCKS4 if int(n) == 4 else ProxyType.HTTP)


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
        if not Patterns.IP.match(host):
            host = gethostbyname(host)
        port = int(port)
        assert self.validate(host, port)
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
            return self.open_socket(sock.family, sock.type, sock.proto,
                                    sock.fileno())
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


class ProxyChecker:

    @staticmethod
    def checkAll(proxies: Collection[Proxy],
                 url: Any = "https://httpbin.org/get",
                 timeout=5,
                 threads=1000):
        with ThreadPoolExecutor(
                max(min(round(len(proxies) * cpu_count()), threads),
                    1)) as executor:
            future_to_proxy = {
                executor.submit(proxy.check, url, timeout): proxy
                for proxy in proxies
            }
            return {
                future_to_proxy[future]
                for future in as_completed(future_to_proxy) if future.result()
            }


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
