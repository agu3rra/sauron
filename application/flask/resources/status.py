import json
from flask import Blueprint, Response

status = Blueprint('status', __name__)

@status.route('/')
def get_status():
    response = {
        "result":True,
        "info":"Sauron sees you..."
    }
    return Response(json.dumps(response),
                    status=200,
                    mimetype='application/json')
