# pylint: disable=missing-docstring

import json

import requests


def test_provider_is_reachable(server_url, provider_info):
    assert provider_info["issuer"] == server_url


def test_provider_static_files(provider_info):
    # try to fetch JWKS which is served by the webserver
    resp = requests.get(provider_info["jwks_uri"])
    assert "keys" in json.loads(resp.text)
