import pytest
# pytest -v
# pytest -v --tb=no -ra
from .tls_check import TlsCheck


class TestTls():

    def setup(self):
        # define a valid target for testing
        self.tls_check = TlsCheck(host='uol.com', port=443)

    def test_invalid_init(self):
        with pytest.raises(TypeError):
            self.tls_check_invalid = TlsCheck(host={}, port='hello')
        with pytest.raises(TypeError):
            self.tls_check_invalid = TlsCheck(host=50, port=433)
        with pytest.raises(TypeError):
            self.tls_check_invalid = TlsCheck(host='hello', port=list(433,332))

    def test_unable_to_connect_network(self):
        self.tls_check.host='191.157.90.1' # somewhere I cannot reach
        server = self.tls_check.connect()
        assert server is None

    def test_connectivity(self):
        server = self.tls_check.connect()
        assert server is not None

    def test_unable_to_connect_ssl(self):
        assert 1==0

    def test_incorrect_proxy_settings(self):
        with pytest.raises(ValueError):
            self.tls_check.scan(proxy={"surver":"uol.com", "port":443})
        with pytest.raises(ValueError):
            self.tls_check.scan(proxy={"server":"uol.com", "part":443})

    def test_proxy_scan(self):
        assert 1==0

    def test_protocols_single(self):
        # Validates a single TLS protocol check
        assert 1==0

    def test_protocols_all(self):
        # Validates each TLS protocol version test works as expected
        assert 1==0

    def test_invalid_protocol_scan(self):
        with pytest.raises(ValueError):
            self.tls_check.scan(protocol='ssl')
        with pytest.raises(ValueError):
            self.tls_check.scan(protocol='random')
        with pytest.raises(ValueError):
            self.tls_check.scan(protocol='tls')

    def test_cipher_suite(self):
        #validates if cipher suite check is working
        assert 1==0