from nmb.NetBIOSProtocol import NBNSProtocol, NetBIOSTimeout


class NetBiosDiscovery(object):
    def __init__(self, address, port=137):
        self.ip = address
        self.port = port
        self.nbns = NBNSProtocol()

    def start(self):
        try:
            response = self.nbns.queryIPForName(self.ip, port=self.port, timeout=30)
        except NetBIOSTimeout:
            print("[!] Error: NetBIOS Name Service response timed out.")
            return False

        return response


