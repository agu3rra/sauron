import re
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
            return None

        return server_info

    def scan_everything(self):
        """
        Scans target for all policy checks

        :returns: (dict)
            [
                {
                    "protocol":"ssl2.0",
                    "is_allowed":False,
                    "has_passed":False,
                    "ciphers_supported":[TLS_RSA_WITH_AES_256_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA]
                    "problematic_ciphers":[TLS_RSA_WITH_AES_128_CBC_SHA]
                },
                {
                    "protocol":"ssl3.0",
                    "is_allowed":False,
                    "has_passed":False,
                    "ciphers_supported":[TLS_RSA_WITH_AES_256_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA]
                    "problematic_ciphers":[TLS_RSA_WITH_AES_128_CBC_SHA]
                },
                ...
            ]
        """
        server_info = self.connect() # Try handshake
        if server_info is None:
            return []
        
        # Retrieve definitions from class to iterate
        synchronous_scanner = SynchronousScanner()
        results = []
        for protocol, policy in self.policies.items():
            is_allowed = policy['allowed']
            command = policy['command']
            scan_result = synchronous_scanner.run_scan_command(
                server_info,
                command)
            
            ciphers = scan_result.accepted_cipher_list
            if len(ciphers) > 0:
                is_supported = True
            else:
                is_supported = False
            
            ciphers_supported = []
            problematic_ciphers = []

            if not is_allowed and not is_supported:
                has_passed = True # don't care about cipher suite list
            elif not is_allowed and is_supported:
                has_passed = False
            elif is_allowed and not is_supported:
                # don't care
                has_passed = True
            elif is_allowed and is_supported:
                #check cipher suite
                has_passed = True # pass unless a problem is detected.
                for cipher in ciphers:
                    name = cipher.name
                    ciphers_supported.append(name)
                    if re.match(r'.*(SHA)$', name):
                        has_passed = False
                        problematic_ciphers.append(name)
            else:
                print('One should never get here!')
                raise OSError('Program logic error.')
            
            result = {
                "protocol":protocol,
                "is_allowed":is_allowed,
                "has_passed":has_passed,
                "ciphers_supported":ciphers_supported,
                "problematic_ciphers":problematic_ciphers,
            }
            results.insert(0, result)