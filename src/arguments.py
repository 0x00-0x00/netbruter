import argparse


def argument_parsing():
    parser = argparse.ArgumentParser()
    sub_parser = parser.add_subparsers(help="Help comand for subparsers")

    parser_post = sub_parser.add_parser('http-post', help="HTTP POST Brute-force attack")
    parser_post.add_argument("-u", "--url", help="URL to attack", required=True, type=str)
    parser_post.add_argument("-p", "--payload", help="Post packet payload (data)", type=str, required=True)
    parser_post.add_argument("-w", "--wordlist", help="Wordlist to guess correct password", required=True, type=str)
    parser_post.add_argument("-e", "--error-string", help="Error string to check correct or incorrect guesses",
                             required=True, type=str)
    parser_post.add_argument("-t", "--tasks", help="How many tasks are going to be used", type=int,
                             default=64)
    parser_post.add_argument("--tor", action="store_true")
    parser_post.add_argument("--tor-address", type=str, help="Tor proxy address and port separated by ':'")
    parser_post.add_argument("--debug", action="store_true", help="Enable debug log messages")

    #  Parse the arguments.
    args = parser.parse_args()
    return args
