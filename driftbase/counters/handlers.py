# -*- coding: utf-8 -*-

import logging
import httplib
import collections
import time

from flask import Blueprint, url_for, g
from flask_restful import Api, Resource, reqparse, abort

from drift.urlregistry import register_endpoints

from driftbase.db.models import CorePlayer, Counter, CounterEntry
from driftbase.utils import get_all_counters, get_counter
from driftbase.players.playergroups import get_playergroup_ids

log = logging.getLogger(__name__)
bp = Blueprint("counters", __name__)
api = Api(bp)

NUM_RESULTS = 100


class CountersApi(Resource):

    get_args = reqparse.RequestParser()

    def get(self):
        """
        Get a list of all 'leaderboards'
        """
        all_counters = g.db.query(Counter).order_by(Counter.name).distinct()

        ret = []
        for s in all_counters:
            ret.append({
                "name": s.name,
                "label": s.label,
                "counter_id": s.counter_id,
                "url": url_for("counters.entry", counter_id=s.counter_id, _external=True)
            })

        resp = api.make_response(ret, httplib.OK)
        resp.cache_control.max_age = 60
        return resp


class CounterApi(Resource):
    get_args = reqparse.RequestParser()
    get_args.add_argument("num", type=int, default=NUM_RESULTS)
    get_args.add_argument("include", type=int, action='append')
    # TODO: Sunset this in favour of player_group
    get_args.add_argument("player_id", type=int, action='append')
    get_args.add_argument("player_group", type=str)
    get_args.add_argument("reverse", type=bool)

    def get(self, counter_id):
        start_time = time.time()
        args = self.get_args.parse_args()
        num = args.get("num") or NUM_RESULTS
        counter = get_counter(counter_id)
        if not counter:
            abort(404)

        filter_player_ids = []
        reverse = not not args.reverse
        if args.player_id:
            filter_player_ids = args.player_id

        query = g.db.query(CounterEntry, CorePlayer)
        query = query.filter(CounterEntry.counter_id == counter_id,
                             CounterEntry.period == "total",
                             CounterEntry.player_id == CorePlayer.player_id,
                             CorePlayer.status == "active",
                             CorePlayer.player_name != u"",)

        if filter_player_ids:
            query = query.filter(CounterEntry.player_id.in_(filter_player_ids))

        if args.player_group:
            filter_player_ids = get_playergroup_ids(args.player_group)
            query = query.filter(CounterEntry.player_id.in_(filter_player_ids))

        if reverse:
            query = query.order_by(CounterEntry.value)
        else:
            query = query.order_by(-CounterEntry.value)
        query = query.limit(num)

        rows = query.all()

        counter_totals = collections.defaultdict(list)
        counter_names = {}
        if args.include:
            all_counters = get_all_counters()
            # inline other counters for the players
            player_ids = [r[0].player_id for r in rows]
            counter_rows = g.db.query(CounterEntry.player_id,
                                      CounterEntry.counter_id,
                                      CounterEntry.value) \
                               .filter(CounterEntry.period == "total",
                                       CounterEntry.player_id.in_(player_ids),
                                       CounterEntry.counter_id.in_(args.include)) \
                               .all()
            for r in counter_rows:
                this_player_id = r[0]
                this_counter_id = r[1]
                this_value = r[2]
                # find the name of this counter. We cache this locally for performance
                try:
                    counter_name = counter_names[this_counter_id]
                except:
                    c = all_counters.get(unicode(this_counter_id), {})
                    name = c.get("name", this_counter_id)
                    counter_names[this_counter_id] = name
                    counter_name = name

                entry = {
                    "name": counter_name,
                    "counter_id": this_counter_id,
                    "counter_url": url_for("playercounters.lookup",
                                           player_id=this_player_id,
                                           counter_id=this_counter_id,
                                           _external=True),
                    "total": this_value
                }
                counter_totals[r.player_id].append(entry)

        ret = []
        for i, row in enumerate(rows):
            player_id = row[0].player_id
            entry = {
                "name": counter["name"],
                "counter_id": counter_id,
                "player_id": player_id,
                "player_name": row[1].player_name,
                "player_url": url_for("players.player", player_id=player_id, _external=True),
                "counter_url": url_for("playercounters.lookup",
                                       player_id=player_id,
                                       counter_id=row[0].counter_id,
                                       _external=True),
                "total": row[0].value,
                "position": i + 1,
                "include": counter_totals.get(player_id, {})
            }
            ret.append(entry)

        resp = api.make_response(ret, httplib.OK)
        resp.cache_control.max_age = 60
        log.info("Returning counters in %.2fsec", time.time() - start_time)

        return resp


api.add_resource(CountersApi, "/counters", endpoint="list")
api.add_resource(CounterApi, "/counters/<int:counter_id>", endpoint="entry")


@register_endpoints
def endpoint_info(current_user):
    ret = {}
    ret["counters"] = url_for("counters.list", _external=True)
    return ret
