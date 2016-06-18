# This file borrowed heavily from:
# https://github.com/mozilla-services/macauthlib

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest

from webob import Request

from pyramid_jwtauth.utils import (strings_differ,
                                   parse_authz_header)


class TestUtils(unittest.TestCase):

    def test_strings_differ(self):
        # We can't really test the timing-invariance, but
        # we can test that we actually compute equality!
        self.assertTrue(strings_differ("", "a"))
        self.assertTrue(strings_differ("b", "a"))
        self.assertTrue(strings_differ("cc", "a"))
        self.assertTrue(strings_differ("cc", "aa"))
        self.assertFalse(strings_differ("", ""))
        self.assertFalse(strings_differ("D", "D"))
        self.assertFalse(strings_differ("EEE", "EEE"))

    def test_parse_authz_header(self):
        def req(authz):
            """Make a fake request with the given authz header."""
            class request:
                environ = {"HTTP_AUTHORIZATION": authz}
            return request

        # Test parsing of a single unquoted parameter.
        params = parse_authz_header(req('Bearer THISISATOKEN'))
        self.assertEqual(params['scheme'], 'Bearer')
        self.assertEqual(params['token'], 'THISISATOKEN')

        # Test parsing on various malformed inputs
        self.assertRaises(ValueError, parse_authz_header, req(None))
        self.assertRaises(ValueError, parse_authz_header, req(""))
        self.assertRaises(ValueError, parse_authz_header, req(" "))

        # Test all those again, but returning a default value
        self.assertEqual(None, parse_authz_header(req(None), None))
        self.assertEqual(None, parse_authz_header(req(""), None))
        self.assertEqual(None, parse_authz_header(req(" "), None))
