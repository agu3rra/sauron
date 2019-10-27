result_template = {
    "category":"",
    "result":False,
    "title":"",
    "description":"",
    "cwe":0,
    "checks":[
        {
            "name":"",
            "result":False,
            "info":"",
        }
    ]
}

scan_response = {
    "response":False,
    "results":[]
}

scan_definitions = {
    "encryption":{
        "no-service":{
            "title":"No service",
            "cwe":0,
            "description":"No service has been detected in the provided host:port. Either it is not properly setup or it is not reachable by this scanner.",
        },
        "missing":{
            "title":"Missing Encryption",
            "cwe":311,
            "description":"The software does not encrypt sensitive or critical information before storage or transmission.The lack of proper data encryption passes up the guarantees of confidentiality, integrity, and accountability that properly implemented encryption conveys. Additional information: https://cwe.mitre.org/data/definitions/311.html",
        },
        "weak":{
            "title":"Weak Encryption",
            "cwe":326,
            "description":"The software stores or transmits sensitive data using an encryption scheme that is theoretically sound, but is not strong enough for the level of protection required. A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources. Additional information: https://cwe.mitre.org/data/definitions/311.html",
        }
    }
}