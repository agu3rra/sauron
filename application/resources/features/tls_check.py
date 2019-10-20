import sslyze
from sslyze.server_connectivity_tester import ServerConnectivityTester, ServerConnectivityError
from sslyze.synchronous_scanner import SynchronousScanner
from sslyze.concurrent_scanner import ConcurrentScanner, PluginRaisedExceptionScanResult
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv13ScanCommand, Tlsv12ScanCommand, Tlsv11ScanCommand, Tlsv10ScanCommand, Sslv30ScanCommand, Sslv20ScanCommand

class TlsCheck(object):

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.policies = {
            "ssl2.0":{
                "allowed":False,
                "command":Sslv20ScanCommand()
            },
            "ssl3.0":{
                "allowed":False,
                "command":Sslv30ScanCommand()
            },
            "tls1.0":{
                "allowed":False,
                "command":Tlsv10ScanCommand()
            },
            "tls1.1":{
                "allowed":False,
                "command":Tlsv11ScanCommand()
            },
            "tls1.2":{
                "allowed":True,
                "command":Tlsv12ScanCommand()
            },
            "tls1.3":{
                "allowed":True,
                "command":Tlsv13ScanCommand()
            },
        }

        if not isinstance(host, str) and not isinstance(port, int):
            raise TypeError('TlsCheck class not properly initialized.')

    def connect(self):
        """
        Establishes SSL connectivity with target host.
        """
        try:
            server_tester = ServerConnectivityTester(
                hostname=self.host,
                port=self.port
            )
            print('Testing connectivity with {server_tester.hostname}:"\
                "{server_tester.port}...')
            server_info = server_tester.perform()
        except ServerConnectivityError as e:
            # Could not establish an SSL connection to the server
            print('Could not connect to {0}: {1}'.format(
                self.host,
                e.error_message))

        return server_info

    def scan_everything(self):
        """
        Scans target for all policy checks

        :returns: (dict)
            {
                "ssl2.0":{
                    "allowed":False,
                    "passed":False,
                    "ciphers":[TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA]
                },
                "ssl3.0":{
                    "allowed":False,
                    "passed":True,
                    "ciphers":[]
                },
                ...
            }
        """
        server_info = self.connect() # Try handshake
        
        # Retrieve definitions from class to iterate
        synchronous_scanner = SynchronousScanner()
        for protocol, policy in self.policies.items():
            is_allowed = policy['allowed']
            command = policy['command']
            scan_result = synchronous_scanner.run_scan_command(
                server_info,
                command)
            ciphers = scan_result.accepted_cipher_list
            if len(ciphers) > 0: # supported
                if not is_allowed:
                    pass

                for cipher in ciphers:
                    print(cipher.name)