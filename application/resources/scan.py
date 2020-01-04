import json
from flask import Blueprint, Response, request
import datetime

from . import features as ft
from .database import MongoService
from .scan_generate_output import ScanOutput

scan = Blueprint('scan', __name__)

@scan.route('/scan', methods=['post'])
def trigger_scan():
    """
    Triggers a scan request. Expected request body:
    {
        "target_host":"example.com",
        "target_port":443,
        "proxy":{
            "server":"myproxy.com",
            "port":8080,
            "user":"yoga",
            "pass":"fire123#flame"
        }
    }
    proxy is optional.
    """

    data = request.get_json()
    print("Scan request received:\n{}".format(json.dumps(data, indent=4)))

    # Validate scan input
    def validate_scan_input(data):
        if "target_host" in data and "target_port" in data:
            return True
        return False
    if not validate_scan_input(data):
        return Response(json.dumps({"result":False,
                                    "info":"This endpoint requires "\
                                        "\"target_host\" and \"target_port\""}),
                    status=400,
                    mimetype='application/json')
    proxy_settings = data.get('proxy', None)

    # Encryption check
    check = ft.EncryptionCheck(host=data['target_host'],
                               port=data['target_port'],
                               proxy=proxy_settings)
    check_results = check.scan()
    results = []
    results.append(ScanOutput.encryption_check(check_results))

    # Generate a False result if any of the results contains a False result key
    final_result = True # It passes the scan until one check does not
    for result in results:
        if result['result'] == False:
            final_result = False

    json_response = {"result":final_result,
                     "results":results}

    # record results on local DB
    document = {
            "created_at": datetime.datetime.now().isoformat(),
            "input": data,
            "output":json_response
    }
    (doc_id, error) = MongoService.insert('scans', document)

    
    if error is not None:
        json_response['errors'] = error

    # Output response to requestor
    return Response(json.dumps(json_response),
                    status=200,
                    mimetype='application/json')
