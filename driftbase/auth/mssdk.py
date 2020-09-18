
import logging

from six.moves import http_client

import requests
from werkzeug.exceptions import Unauthorized
from flask import request
from flask_smorest import abort
from driftbase.auth import get_provider_config
from hashlib import md5
import json

import time 
from drift.core.extensions.schemachecker import check_schema

from .authenticate import authenticate as base_authenticate

log = logging.getLogger(__name__)


# MSSDK provider details schema
mssdk_provider_schema = {
    'type': 'object',
    'properties':
    {
        'provider_details':
        {
            'type': 'object',
            'properties':
            {
                'open_id': {'type': 'string'},
                'session_id': {'type': 'string'},
                'nonce': {'type': 'string'},
            },
            'required': ['open_id', 'session_id', 'nonce'],
        },
    },
    'required': ['provider_details'],
}


def authenticate(auth_info):
    assert auth_info['provider'] == 'mssdk'
    provider_details = auth_info.get('provider_details')
    automatic_account_creation = auth_info.get("automatic_account_creation", True)

    if provider_details.get('provisional', False):
        if len(provider_details['username']) < 1:
            abort_unauthorized("Bad Request. 'username' cannot be an empty string.")
        username = "mssdk:" + provider_details['username']
        password = provider_details['password']
        return base_authenticate(username, password, True or automatic_account_creation)
    identity_id = validate_mssdk_ticket()
    username = "mssdk:" + identity_id
    return base_authenticate(username, "", True or automatic_account_creation)


def validate_mssdk_ticket():
    """Validate MSSDK ticket from /auth call."""

    ob = request.get_json()
    check_schema(ob, mssdk_provider_schema, "Error in request body.")
    provider_details = ob['provider_details']
    # Get mssdk authentication config
    mssdk_config = get_provider_config('mssdk')

    if not mssdk_config:
        abort(http_client.SERVICE_UNAVAILABLE, description="MSSDK authentication not configured for current tenant")

    # Call validation and authenticate if ticket is good
    identity_id = run_ticket_validation(
        open_id=provider_details['open_id'],
        session_id=mssdk_config['session_id'],
        nonce=provider_details['nonce'],
        app_key=mssdk_config['app_key']
    )

    return identity_id

def add_mssdk_headers(headers, body):
    """
        The API requires a timestamp, the app key, and a signature
        that is a hashed combination of the parameters incorporating the
        app secret to ensure there has been no tampering and it is official.
    """
    mssdk_config = get_provider_config('mssdk')
    headers.update({
        'Timestamp': time.time(),
        'AppKey': mssdk_config.get('app_key')
        })   
    secret = mssdk_config.get('app_secret')
    strings = [secret]
    # they want it in lexicographical order...
    for key, value in sorted(headers.items(), key=lambda x: x[0]):
        strings.append('{}={}'.format(key, value))
    strings.append(str(json.dumps(body)))
    strings.append(secret)
    signature = md5('&'.join(strings))
    headers.update({'Signature': signature,
                    'Content-Type': 'application/json'})
    
def run_ticket_validation(open_id, session_id, nonce, app_key):
    """
    Validates MSSDK session ticket.

    Returns a unique ID for this player.
    """
    headers = {
        'Nonce': nonce,
    }
    body = {
        'appkey': app_key,
        'openId': open_id,
        'sessionId': session_id
    }
    add_mssdk_headers(headers, body)
    url = 'http://internal-gw.uu.cc/internal-gateway/ms-public-oauth2/sdk_/oauth/checkSession'
    try:
        ret = requests.post(url, data=body, headers=headers)
    except requests.exceptions.RequestException as e:
        log.warning("MSSDK authentication request failed: %s", e)
        abort_unauthorized("MSSDK ticket validation failed. Can't reach MSSDK platform.")

    if ret.status_code != 200 or not ret.json().get('code', 0):
        log.warning("Failed MSSDK authentication. Response code %s: %s", ret.status_code, ret.json())
        abort_unauthorized("User {} not authenticated on MSSDK platform.".format(open_id))

    player_id = ret.json().get('result', {}).get('data', {}).get('player_id')
    if not player_id:
        """Probably won't happen...
        """
        log.warning("Failed MSSDK authentication. Missing player_id in response: %s", ret.json())
        abort_unauthorized("User {} not authenticated on MSSDK platform.".format(open_id))
    return player_id


def abort_unauthorized(description):
    """Raise an Unauthorized exception.
    """
    raise Unauthorized(description=description)
