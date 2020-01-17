import json
from flask import Blueprint, Response, request

from .database import MongoService
from .authorization import authorized

scans = Blueprint('scans', __name__)

@scans.route('/scans', methods=['get'])
@authorized(roles_required=['admin'])
def get_scans():
    """
    Reads all scans
    """
    (data, error) = MongoService.read('scans')
    if error is not None:
        response = {
            "info": "Error retrieving data.",
            "detail": error
        }
        return Response(json.dumps(response),
                        status=500,
                        mimetype='application/json')
    return Response(json.dumps(data),
                        status=200,
                        mimetype='application/json')