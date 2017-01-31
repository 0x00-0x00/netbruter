import argparse

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


def argument_parsing():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", help="URL to attack", required=True, type=str)
    parser.add_argument("-p", "--payload", help="Post packet payload (data)", type=str, required=True)
    parser.add_argument("-w", "--wordlist", help="Wordlist to guess correct password", required=True, type=str)
    parser.add_argument("-e", "--error-string", help="Error string to check correct or incorrect guesses",
                        required=True, type=str)
    parser.add_argument("--tor", action="store_true")
    parser.add_argument("--tor-address", type=str, help="Tor proxy address and port separated by ':'")
    parser.add_argument("--debug", action="store_true", help="Enable debug log messages")

    #  Parse the arguments.
    args = parser.parse_args()

    #  Abort the program if tor check fails.
    if tor_parse(args) is False:
        return None
    return args
