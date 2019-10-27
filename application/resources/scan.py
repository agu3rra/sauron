import json
from flask import Blueprint, Response
from .scan_templates import scan_definitions, result_template


scan = Blueprint('scan', __name__)

@scan.route('/scan')
def trigger_scan():
    return Response(json.dumps({"status":"not yet implemented"}),
                    status=500,
                    mimetype='application/json')