import json
from flask import Blueprint, Response, request
from .scan_templates import scan_definitions, result_template
from . import features as ft


scan = Blueprint('scan', __name__)

@scan.route('/scan', methods=['post'])
def trigger_scan():
    data = request.get_json()
    
    # Validate scan input
    def validate_scan_input(data):
        if "target_host" in data and "target_port" in data:
            return True
        return False        
    if not validate_scan_input(data):
        return Response(json.dumps({"response":False,
                                    "info":"This endpoint requires "\
                                        "\"target_host\" and \"target_port\""}),
                    status=400,
                    mimetype='application/json')
    proxy_settings = data.get('proxy', None)


    # Encryption check
    category='encryption'
    definitions = scan_definitions['encryption']
    check = ft.EncryptionCheck(host=data['target_host'],
                               port=data['target_port'],
                               proxy=proxy_settings)
    check_results = check.scan()
    
    if len(check_results) == 0:
        result_definition = definitions['no-service']
        result={}
        result['category']=category
        result['result']=False
        result['title']=result_definition['title']
        result['description']=result_definition['description']
        result['cwe']=result_definition['cwe']
        result['checks']=[]
        return Response(json.dumps({"response":False,
                                    "results":[result]}),
                        status=200,
                        mimetype='application/json')
    else:
        results=[]
        for one_result in check_results:
            # RESUME HERE
            pass

    return Response(json.dumps({"status":"not yet implemented"}),
                    status=500,
                    mimetype='application/json')

    