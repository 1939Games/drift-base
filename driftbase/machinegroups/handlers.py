# -*- coding: utf-8 -*-
"""
    These are endpoints for battleserver run configurations
"""

import logging

from six.moves import http_client

from flask import Blueprint, request, url_for, g
from flask_restful import Api, Resource, reqparse, abort

from drift.core.extensions.schemachecker import simple_schema_request
from drift.urlregistry import register_endpoints
from drift.core.extensions.jwt import requires_roles

from driftbase.models.db import MachineGroup

log = logging.getLogger(__name__)
bp = Blueprint("machinegroups", __name__)
api = Api(bp)


class MachineGroupsAPI(Resource):
    get_args = reqparse.RequestParser()
    get_args.add_argument("name", type=str)
    get_args.add_argument("rows", type=int, required=False)

    @requires_roles("service")
    def get(self):
        args = self.get_args.parse_args()
        num_rows = args.get("rows") or 100
        query = g.db.query(MachineGroup)
        if args["name"]:
            query = query.filter(MachineGroup.name == args["name"])
        query = query.order_by(-MachineGroup.machinegroup_id)
        query = query.limit(num_rows)
        rows = query.all()
        ret = []
        for row in rows:
            record = row.as_dict()
            record["url"] = url_for("machinegroups.entry",
                                    machinegroup_id=row.machinegroup_id, _external=True)
            ret.append(record)

        return ret

    @requires_roles("service")
    @simple_schema_request({
        "name": {"type": "string", },
        "description": {"type": "string", },
        "runconfig_id": {"type": "number", },
    }, required=["name"])
    def post(self):
        args = request.json
        log.info("creating a new machine group")

        machinegroup = MachineGroup(name=args.get("name"),
                                    description=args.get("description"),
                                    runconfig_id=args.get("runconfig_id"),
                                    )
        g.db.add(machinegroup)
        g.db.commit()
        machinegroup_id = machinegroup.machinegroup_id
        resource_uri = url_for("machinegroups.entry", machinegroup_id=machinegroup_id,
                               _external=True)
        response_header = {
            "Location": resource_uri,
        }
        log.info("Machine Group %s has been created with name '%s'",
                 machinegroup_id, args.get("name"))

        return {"machinegroup_id": machinegroup_id,
                "url": resource_uri
                }, http_client.CREATED, response_header


class MachineGroupAPI(Resource):
    """
    Information about specific machines
    """
    @requires_roles("service")
    def get(self, machinegroup_id):
        """
        Get information about a single battle server machine.
        Just dumps out the DB row as json
        """
        row = g.db.query(MachineGroup).get(machinegroup_id)
        if not row:
            log.warning("Requested a non-existant machine group %s", machinegroup_id)
            abort(http_client.NOT_FOUND, description="Machine Group not found")
        record = row.as_dict()
        record["url"] = url_for("machinegroups.entry", machinegroup_id=machinegroup_id,
                                _external=True)

        log.info("Returning info for run config %s", machinegroup_id)

        return record

    @requires_roles("service")
    @simple_schema_request({
        "name": {"type": "string", },
        "description": {"type": "string", },
        "runconfig_id": {"type": "number", },
    }, required=[])
    def patch(self, machinegroup_id):
        args = request.json

        machinegroup = g.db.query(MachineGroup).get(machinegroup_id)
        if args.get("name"):
            machinegroup.name = args["name"]
        if args.get("description"):
            machinegroup.description = args["description"]
        if args.get("runconfig_id"):
            machinegroup.runconfig_id = args["runconfig_id"]
        g.db.commit()
        return "OK"


api.add_resource(MachineGroupsAPI, '/machinegroups', endpoint="list")
api.add_resource(MachineGroupAPI, '/machinegroups/<int:machinegroup_id>', endpoint="entry")


@register_endpoints
def endpoint_info(*args):
    ret = {
        "machinegroups": url_for("machinegroups.list", _external=True),
    }
    return ret
