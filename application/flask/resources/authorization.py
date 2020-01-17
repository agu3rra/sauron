from flask import Response, request
import json

def authorized(roles_required):
    """
    Authorized an endpoint for a given role.
    """
    def authorized_function(endpoint):
        def call(*args, **kwargs):
            token = request.headers.get('Authorization', None)
            if token is None:
                response = json.dumps({
                    "info": "unauthorized",
                    "detail": "Bearer token missing."})
                return Response(response,
                                status=401,
                                mimetype='application/json')
            print('endpoint: {}\nroles: {}\nrequest: {}'.format(
                endpoint, roles_required, request))


            # Perform authorization denial here if required.


            return endpoint(*args, **kwargs)
        return call
    return authorized_function