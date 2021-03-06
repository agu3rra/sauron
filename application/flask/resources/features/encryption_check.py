import re
import requests
import sslyze
from sslyze.server_connectivity_tester import ServerConnectivityTester, ServerConnectivityError
from sslyze.synchronous_scanner import SynchronousScanner
from sslyze.concurrent_scanner import ConcurrentScanner, PluginRaisedExceptionScanResult
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv13ScanCommand, Tlsv12ScanCommand, Tlsv11ScanCommand, Tlsv10ScanCommand, Sslv30ScanCommand, Sslv20ScanCommand
from sslyze.ssl_settings import HttpConnectTunnelingSettings

class EncryptionCheck(object):

    def __init__(self, host, port, proxy=None):
        """
        :param proxy: (dict) Default: None; Set this one up if you wish to use
                a proxy to hit your target host. E.g.:
                {
                    "server":"someproxy.com",
                    "port":6000,
                    "user":"optional",
                    "pass":"secretpass"
                }
        """
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

        if not isinstance(host, str) or not isinstance(port, int):
            raise TypeError('EncryptionCheck class not properly initialized.')
        
        # Proxy setup
        if proxy is not None:
            if not ("server" in proxy and "port" in proxy):
                raise ValueError('Invalid proxy settings detected.')
            proxy_server = proxy['server']
            proxy_port = proxy['port']
            proxy_user = proxy.get('user', None)
            proxy_pass = proxy.get('pass', None)
            tunnel_settings = HttpConnectTunnelingSettings(
                proxy_server,
                proxy_port,
                basic_auth_user=proxy_user,
                basic_auth_password=proxy_pass)
        else:
            tunnel_settings = None
        self.tunnel = tunnel_settings
        self.proxy = proxy

    def connect(self):
        """
        Establishes SSL connectivity with target host.

        :param proxy: (HttpConnectTunnelingSettings)
        """
        try:
            server_tester = ServerConnectivityTester(
                hostname=self.host,
                port=self.port,
                http_tunneling_settings=self.tunnel
            )
            print("Testing connectivity with {0}:{1}".format(self.host,
                                                             self.port))
            server_info = server_tester.perform(network_timeout=2)
            print("Connection established")
        except ServerConnectivityError as e:
            # Could not establish an SSL connection to the server
            print("Could not connect to {0}:{1}".format(self.host,
                                                        e.error_message))
            return None

        return server_info

    def check_service(self):
        """
        validates if there is an http service running in case ssl handshake 
        fails.

        :return: True if service found (HTTP status 200 - 499).
        """
        proxy_string = "http://"
        if self.proxy is not None:
            if "user" in self.proxy and "pass" in self.proxy:
                proxy_string += "{}:{}@".format(self.proxy['user'],
                                                self.proxy['pass'])
            proxy_string += "{}:{}".format(self.proxy['server'],
                                           self.proxy['port'])
            proxies = {
                "http": proxy_string,
                "https": proxy_string,
            }
        else:
            proxies = None
        url = "http://{}:{}".format(self.host, self.port)
        try:
            response = requests.get(url, proxies=proxies, timeout=2)
            status = response.status_code
            if status >= 200 and status < 500:
                if status == 407:
                    print("proxy authorization error 407")
                    return False
                print("Service is up on http. Status code: {}".format(status))
                return True
            print("Service is down on http. Status code: {}".format(status))
            return False
        except Exception as e:
            print("Service unresponsive. Exception generated:\n{}".format(e))
            return False
        
        

    def scan(self, protocol='all'):
        """
        Scans target for all policy checks

        :param protocol: (str) Default: all; It can also be one of the keys of
                         self.policies

        :returns: (array) of (dict)
            [] empty array when there is no service running in host:port.
            [
                {
                    "protocol":"ssl2.0",
                    "is_supported":True,
                    "is_allowed":False,
                    "has_passed":False,
                    "ciphers_supported":[TLS_RSA_WITH_AES_256_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA]
                    "problematic_ciphers":[TLS_RSA_WITH_AES_128_CBC_SHA]
                },
                ...
            ]
        """
        # Define if one of all policies will be checked
        policies = {}
        if protocol == 'all':
            policies = self.policies
        elif protocol in list(self.policies):
            policies[protocol] = self.policies[protocol]
        else:
            raise ValueError('Invalid protocol selected for scanning.')

        # Try handshake
        server_info = self.connect()
        if server_info is None:
            message = "SSL Handshake failed. Checking service port for "\
                "unencrypted channels."
            print(message)
            if self.check_service():
                return [
                    {
                        "protocol":'unencrypted',
                        "is_supported":True,
                        "is_allowed":False,
                        "has_passed":False,
                        "ciphers_supported":[],
                        "problematic_ciphers":[],
                    }
                ]
            else:
                return []
        
        # Retrieve definitions from class to iterate
        print("Initializing synchronous SSL scan.")
        synchronous_scanner = SynchronousScanner()
        results = []
        for protocol, policy in policies.items():
            print("Checking {} protocol support".format(protocol))
            is_allowed = policy['allowed']
            command = policy['command']
            scan_result = synchronous_scanner.run_scan_command(
                server_info,
                command)
            
            # Detect cipher support
            ciphers = scan_result.accepted_cipher_list
            ciphers_supported = []
            problematic_ciphers = []
            for cipher in ciphers:
                name = cipher.name
                ciphers_supported.append(name)
                if re.match(r'.*(SHA)$', name) or \
                    (name.find('RSA_WITH_AES') == -1):
                    problematic_ciphers.append(name)

            # Determine support based on ciphers            
            if len(ciphers_supported) > 0:
                is_supported = True
            else:
                is_supported = False

            # Determine if the check has passed for this protocol
            if not is_allowed and not is_supported:
                has_passed = True # don't care about cipher suite list
            elif not is_allowed and is_supported:
                has_passed = False
            elif is_allowed and not is_supported:
                has_passed = True
            elif is_allowed and is_supported:
                if len(problematic_ciphers) > 0:
                    has_passed = False
                else:
                    has_passed = True
            else:
                print('One should never get here!')
                raise OSError('Program logic error.')
            
            result = {
                "protocol":protocol,
                "is_supported":is_supported,
                "is_allowed":is_allowed,
                "has_passed":has_passed,
                "ciphers_supported":ciphers_supported,
                "problematic_ciphers":problematic_ciphers,
            }
            results.insert(0, result)
        print("SSL scan completed.")
        return results