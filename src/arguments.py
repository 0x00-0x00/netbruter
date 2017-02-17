import argparse


def argument_parsing():
    parser = argparse.ArgumentParser()
    sub_parser = parser.add_subparsers(help="Help comand for subparsers")

    parser_post = sub_parser.add_parser('http-post', help="HTTP POST Brute-force attack")
    parser_post.add_argument("-pu", "--pre-url", help="Pre-URL for multi-page form websites.")
    parser_post.add_argument("-pp", "--pre-payload", help="Pre-payload to use at pre-page form.")
    parser_post.add_argument("-u", "--url", help="URL to attack", required=True, type=str)
    parser_post.add_argument("-l", "--login", help="Login to attack", type=str)
    parser_post.add_argument("-p", "--payload", help="Post packet payload (data)", type=str, required=True)
    parser_post.add_argument("-w", "--wordlist", help="Wordlist to guess correct password", required=True, type=str)
    parser_post.add_argument("-e", "--error-string", help="Error string to check correct or incorrect guesses",
                             required=True, type=str)
    parser_post.add_argument("-t", "--tasks", help="How many tasks are going to be used", type=int,
                             default=64)
    parser_post.add_argument("--tor", action="store_true")
    parser_post.add_argument("--tor-address", type=str, help="Tor proxy address and port separated by ':'")
    parser_post.add_argument("--debug", action="store_true", help="Enable debug log messages")

    parser_smb = sub_parser.add_parser('netbios', help="NetBIOS Brute-force attack")
    parser_smb.add_argument("--ip", required=True, type=str, help="Remote host IP address.")
    parser_smb.add_argument("-p", "--port", required=True, type=str, help="Remote host port number.", default=445)
    parser_smb.add_argument("-w", "--wordlist", required=True, type=str, help="Wordlist to guess a correct password.")

    #  Parse the arguments.
    args = parser.parse_args()
    return args
