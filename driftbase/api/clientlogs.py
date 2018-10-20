# -*- coding: utf-8 -*-

import logging

from six.moves import http_client

from flask import request, url_for
from flask_restplus import Namespace, Resource, reqparse, abort

from drift.core.extensions.urlregistry import Endpoints
from drift.core.extensions.jwt import current_user

from driftbase.utils import verify_log_request

log = logging.getLogger(__name__)
namespace = Namespace("clientlogs", "Client Logs")
endpoints = Endpoints()

clientlogger = logging.getLogger("clientlog")
eventlogger = logging.getLogger("eventlog")


def drift_init_extension(app, api, **kwargs):
    api.add_namespace(namespace)
    endpoints.init_app(app)


@namespace.route('/', endpoint='clientlogs')
class ClientLogsAPI(Resource):

    no_jwt_check = ["POST"]

    def post(self):
        """
        Public endpoint, called from the client for debug logging

        Example usage:

        POST http://localhost:10080/clientlogs

        [
            {"category": "BuildingDatabase",
             "message": "Missing building data",
             "level": "Error",
             "timestamp": "2015-01-01T10:00:00.000Z"
            }
        ]

        """
        verify_log_request(request)
        args = request.json
        if not isinstance(args, list):
            args = [args]
        player_id = current_user["player_id"] if current_user else None

        for event in args:
            event["player_id"] = player_id
            clientlogger.info("clientlog", extra=event)

        return "OK", http_client.CREATED


@endpoints.register
def endpoint_info(*args):
    return {
        "clientlogs": url_for("clientlogs", _external=True),
    }
