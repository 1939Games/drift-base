# -*- coding: utf-8 -*-

import os
from os.path import abspath, join
config_file = abspath(join(__file__, "..", "..", "..", "config", "config.json"))
os.environ.setdefault("drift_CONFIG", config_file)

import httplib
import unittest, responses, mock
import json, requests
from mock import patch
from drift.systesthelper import setup_tenant, remove_tenant, DriftBaseTestCase, big_number


def setUpModule():
    setup_tenant()


def tearDownModule():
    remove_tenant()


class UsersTest(DriftBaseTestCase):
    """
    Tests for the /clients endpoint
    """
    def test_users(self):
        self.auth()
        resp = self.get("/")
        my_user_id = resp.json()["current_user"]["user_id"]

        resp = self.get("/users")
        self.assertTrue(isinstance(resp.json(), list))

        resp = self.get("/users/%s" % my_user_id)
        self.assertTrue(isinstance(resp.json(), dict))

        resp = self.get("/users/{}".format(big_number), expected_status_code=httplib.NOT_FOUND)

    def test_noauth(self):
        r = self.get("/users", expected_status_code=httplib.UNAUTHORIZED)
        self.assertIn("error", r.json())
        self.assertIn("code", r.json()["error"])
        self.assertIn("Authorization Required", r.json()["error"]["description"])


if __name__ == '__main__':
    unittest.main()
