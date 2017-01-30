import aiosocks
import random
from aiosocks.connector import SocksConnector, HttpProxyAddr, HttpProxyAuth


def generate_credentials():
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return ''.join([random.choice(charset) for x in range(8)]), ''.join([random.choice(charset) for x in range(8)])


def parse_proxy_address(string):
    return tuple(string.split(":"))


def get_tor_connector(string):
    ip, port = parse_proxy_address(string)
    login, password = generate_credentials()
    addr = aiosocks.Socks5Addr(ip, int(port))
    auth = aiosocks.Socks5Auth(login, password=password)
    conn = SocksConnector(proxy=addr, proxy_auth=auth, remote_resolve=True)
    return conn
