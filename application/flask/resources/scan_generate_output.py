from .scan_templates import scan_definitions, result_template


# Scan output format generation
class ScanOutput():

    @staticmethod
    def encryption_check(check_results):
        response = True # It passes all checks until one fails.
        category='encryption'
        definitions = scan_definitions['encryption']
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
            print("Service did not respond.")
            response = False
            result = process_encryption_check(outcome_definition='no-service',
                                            outcome_result=False,
                                            checks = [])
        # Missing encryption (HTTP plain text)
        elif len(check_results) == 1:
            print("Plain text protocol supported.")
            response = False
            result = process_encryption_check(outcome_definition='missing',
                                            outcome_result=False,
                                            checks = [])
        # SSL handshake worked.
        else:
            print("Processing SSL protocols supported.")
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
        return result