import json
from flask import Blueprint, Response

scan = Blueprint('scan', __name__)

@scan.route('/scan')
def trigger_scan():
    return Response(json.dumps({"status":"not yet implemented"}),
                    status=500,
                    mimetype='application/json')