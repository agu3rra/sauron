import pytest
from .tls_check import TlsCheck


class TestTls():

    def setup(self):
        # define a valid target for testing
        self.tls_check = TlsCheck(host='uol.com', port=443)

    def test_invalid_init(self):
        pass

    def test_unable_to_connect_network(self):
        pass

    def test_unable_to_connect_ssl(self):
        pass

    def test_protocol(self):
        # Validates each TLS protocol version test works as expected
        
        pass

    def test_cipher_suite(self):
        #validates if cipher suite check is working
        pass