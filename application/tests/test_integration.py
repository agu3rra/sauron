import os
import pytest
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
import sys
sys.path.append(BASE_DIR)

from app import app

class TestIntegration():

    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client

    def test_status(self, client):
        response = client.get('/')
        response = response.json
        assert isinstance(response, dict)
        assert response['result'] == True
        assert response['info'].find('Sauron') != -1

    def test_scan(self, client):
        scan_data = {
            "target_host":"uol.com",
            "target_port":443
        }
        response = client.post('/scan', json=scan_data)
        response = response.json
        assert isinstance(response, dict)
        assert response['result'] == False
        num_encryption_checks = len(response['results'][0]['checks'])
        assert num_encryption_checks == 6