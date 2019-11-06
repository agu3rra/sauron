import os
import pytest
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
import sys
sys.path.append(BASE_DIR)

from app import app

class TestIntegration():

    def setup(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    def test_status(self):
        response = self.client.get('/')
        response = response.json
        assert isinstance(response, dict)
        assert response['result'] == True
        assert response['info'].find('Sauron') != -1

    @pytest.mark.parametrize(
        "host, port, proxy, exp_result, exp_checks",
        [
            pytest.param("uol.com", 443, None, False, 6),
            pytest.param("pluralsight.com", 443, None, False, 6),
        ]
    )
    def test_scan(self, host, port, proxy, exp_result, exp_checks):
        scan_data = {
            "target_host":host,
            "target_port":port
        }
        response = self.client.post('/scan', json=scan_data)
        response = response.json
        assert isinstance(response, dict)
        assert response['result'] == exp_result
        num_encryption_checks = len(response['results'][0]['checks'])
        assert num_encryption_checks == exp_checks