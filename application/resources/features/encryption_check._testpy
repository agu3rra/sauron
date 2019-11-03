import pytest
# pytest -v
# pytest -v --tb=no -ra
from .encryption_check import EncryptionCheck


class TestTls():

    def setup(self):
        # define a valid target for testing
        self.check = EncryptionCheck(host='uol.com', port=443)

    def test_invalid_init(self):
        with pytest.raises(TypeError):
            self.check_invalid = EncryptionCheck(host={}, port='hello')
        with pytest.raises(TypeError):
            self.check_invalid = EncryptionCheck(host=50, port=433)
        with pytest.raises(TypeError):
            self.check_invalid = EncryptionCheck(host='hello', port=list(433,332))

    def test_unable_to_connect_network(self):
        self.check.host='191.157.90.1' # somewhere I cannot reach
        server = self.check.connect()
        assert server is None

    def test_connectivity(self):
        server = self.check.connect()
        assert server is not None

    def test_plain_http_service(self):
        # Try to connect to a plain http server
        check = EncryptionCheck(host='caixa.gov.br', port=80)
        results = check.scan()
        assert len(results) == 1
        result = results.pop()
        assert result['protocol'] == 'unencrypted'

    def test_incorrect_proxy_settings(self):
        with pytest.raises(ValueError):
            _ = EncryptionCheck(host='uol.com',
                        port=443,
                        proxy={"surver":"uol.com", "port":443})
        with pytest.raises(ValueError):
            _ = EncryptionCheck(host='uol.com',
                        port=443,
                        proxy={"server":"uol.com", "part":443})

    def test_proxy_scan(self):
        # I need to spin up a proxy server before I can test this
        assert True==False

    def test_protocols_single(self):
        # Validates a single TLS protocol check
        results = self.check.scan(protocol='tls1.2')
        assert len(results) == 1
        result = results.pop()
        assert result['protocol'] == 'tls1.2'
        assert result['is_supported'] == False
        assert result['is_allowed'] == True
        assert result['has_passed'] == True
        assert result['ciphers_supported'] == []
        assert result['problematic_ciphers'] == []

    def test_protocols_all(self):
        # Validates each TLS protocol version test works as expected
        results = self.check.scan()
        assert len(results) == 6
        for result in results:
            assert result['protocol'] in self.check.policies

    def test_invalid_protocol_scan(self):
        with pytest.raises(ValueError):
            self.check.scan(protocol='ssl')
        with pytest.raises(ValueError):
            self.check.scan(protocol='random')
        with pytest.raises(ValueError):
            self.check.scan(protocol='tls')
