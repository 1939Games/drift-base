# -*- coding: utf-8 -*-

import json

from flask import g
from driftbase.db.models import Counter, MatchEvent
import logging
log = logging.getLogger(__name__)

EXPIRE_SECONDS = 86400


def get_all_counters(force=False):
    def get_all_counters_from_db():
        counters = g.db.query(Counter).all()
        all_counters = {}
        for c in counters:
            counter = {
                "counter_id": c.counter_id,
                "name": c.name,
                "counter_type": c.counter_type,
            }
            all_counters[c.counter_id] = counter
            all_counters[c.name] = counter
        return all_counters
    val = g.redis.get("counters")
    if not val or force:
        all_counters = get_all_counters_from_db()
        g.redis.set("counters", json.dumps(all_counters), expire=60 * 10)
    else:
        try:
            all_counters = json.loads(val)
        except:
            log.error("Cannot decode '%s'", val)
            raise
    return all_counters


def get_counter(counter_key):
    counters = get_all_counters()
    try:
        return counters[unicode(counter_key)]
    except KeyError:
        log.info("Counter '%s' not found in cache. Fetching from db", counter_key)
        log.info("Counter cache contains: %s" % (counters.keys()))
        counters = get_all_counters(force=True)
        return counters.get(counter_key, None)
    return None


def clear_counter_cache():
    g.redis.delete("counter_names")


def log_match_event(match_id, player_id, event_type_name, details=None, db_session=None):

    if not db_session:
        db_session = g.db

    log.info("Logging player event to DB: player_id=%s, event=%s", player_id, event_type_name)
    event = MatchEvent(event_type_id=None,
                       event_type_name=event_type_name,
                       player_id=player_id,
                       match_id=match_id,
                       details=details)
    db_session.add(event)
    db_session.commit()


class UserCache(object):
    """
    Simple cache for user session information
    """
    def __init__(self, tenant=None, service_name=None):
        self.cache = g.redis

    def _key(self, user_id):
        key = "user:{}".format(user_id)
        return key

    def get_all(self, user_id):
        ret = self.cache.get(self._key(user_id))
        if ret:
            ret = json.loads(ret)
            return ret
        return None

    def set_all(self, user_id, val):
        self.cache.set(self._key(user_id), json.dumps(val), expire=EXPIRE_SECONDS)

    def get(self, user_id, key):
        contents = self.get_all(user_id)
        ret = (contents or {}).get(key, None)
        return ret

    def set(self, user_id, key, val):
        contents = self.get_all(user_id)
        if not contents:
            contents = {}
        contents[key] = val
        self.set_all(user_id, contents)

    def delete(self, user_id):
        return self.cache.delete(self._key(user_id))
