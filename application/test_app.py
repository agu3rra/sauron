import os
import tempfile
import pytest

from app import app

@pytest.fixture
def client():
    db_fb, app.config['DATABASE'] = tempfile.mkstemp()
    app.config['TESTING'] = True

    with app.test_client() as client:
        yield client
    
    os.close(db_fb)
    os.unlink(app.config['DATABASE'])

def test_empty_db(client):
    response = client.get('/')
    breakpoint()
    assert isinstance(response.data, dict)
    

