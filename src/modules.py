from netbruter.http_post import Netbrute as NetBrutePOST
from netbruter.resume import restore_script
import gzip
import os


def tor_parse(args):
    """
    Checks if Tor boolean is set, then checks if the tor-address is set.
    :param args: Arguments
    :return: True or False
    """
    if not args.tor:
        return True

    if not args.tor_address:
        print("[!] Tor address not supplied by the user.")
        return False
    return True


def http_post(args, loop):
    if tor_parse(args) is False:
        return None
    net = NetBrutePOST(loop, pre_url=args.pre_url, pre_payload=args.pre_payload, target_url=args.url, login=args.login, payload_model=args.payload, wordlist=args.wordlist, error_string=args.error_string, tasks=args.tasks, tor=args.tor, tor_address=args.tor_address, debug=args.debug)

    try:
        loop.run_until_complete(net.initiate(loop))
    except KeyboardInterrupt:
        print("[+] Saving session data into '{0}' ...".format(net.session_name))
        restore_script()
        if net.tried_passwords > 100 and os.path.isfile(net.session_name):
            with open(net.session_name, "rb") as f:
                data = f.read()
            with gzip.open(net.session_name, "wb", compresslevel=9) as f:
                f.write(data)
        print("[+] Data session has been saved.")
    return 0


def netbios_attack(args, loop):

    return 0
