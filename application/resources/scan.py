import json
from flask import Blueprint, Response, request
from .scan_templates import scan_definitions, result_template
from . import features as ft
from pymongo import MongoClient

localdb = 'mongodb://localhost:27017/'
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

    response = True # It passes all checks until one fails.

    # Encryption check
    category='encryption'
    definitions = scan_definitions['encryption']
    check = ft.EncryptionCheck(host=data['target_host'],
                               port=data['target_port'],
                               proxy=proxy_settings)
    check_results = check.scan()
    
    def process_encryption_check(outcome_definition,
                                 outcome_result,
                                 checks):
        """
        :param outcome_definition: (str) The definition key to pull text from 
            scan_templates
        :param outcome_result: (bool) the final outcome of this check
        :param checks: (arr) the array of checks.
        """
        result_definition = definitions[outcome_definition]
        result={}
        result['category']=category
        result['result']=outcome_result
        result['title']=result_definition['title']
        result['description']=result_definition['description']
        result['cwe']=result_definition['cwe']
        result['checks']=checks
        return result

    # Service did not respond
    if len(check_results) == 0:
        response = False
        result = process_encryption_check(outcome_definition='no-service',
                                          outcome_result=False,
                                          checks = [])
    # Missing encryption (HTTP plain text)
    elif len(check_results) == 1:
        response = False
        result = process_encryption_check(outcome_definition='missing',
                                          outcome_result=False,
                                          checks = [])
    # SSL handshake worked.
    else:
        checks = []
        # if at least one check failed, then response False
        for protocol in check_results:
            name = protocol['protocol']
            has_passed = protocol['has_passed']
            if has_passed:
                this_result=True
                info = "Application has passed this check successfully."
            else:
                this_result=False
                is_allowed = protocol['is_allowed']
                if is_allowed: # ciphers issue
                    ciphers_output = ""
                    for cipher in protocol['problematic_ciphers']:
                        ciphers_output += "{}; ".format(cipher)
                    info = "This TLS protocol version is ok to use, but you '\
                        'have selected a set of insecure ciphers: {}".\
                        format(ciphers_output)
                else: # tls version issue
                    info = "Encryption protocol version is insecure."
                outcome_result=False
                response = False
            checks.append({
                "name":name,
                "result":this_result,
                "info":info,
                "details":protocol,
            })
        result = process_encryption_check(outcome_definition='weak',
                                          outcome_result=response,
                                          checks = checks)

        # record results on local DB
        try:
            client = MongoClient(localdb)
            scans_db = client['scans-db']
            sauron_collection = scans_db['sauron-collection']
            document = {
                "scan_input": data,
                "results":[result]
            }
            document = sauron_collection.insert_one(document)
        except Exception as e:
            print('Exception occurred while saving scan results:\n{}'.format(e))

    # Output response to requestor
    return Response(json.dumps({"result":response,
                                "results":[result]}),
                    status=200,
                    mimetype='application/json')
