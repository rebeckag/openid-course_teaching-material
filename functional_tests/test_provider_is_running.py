import json

import requests


def test_provider_is_reachable(server_url):
    resp = requests.get(server_url + "/.well-known/openid-configuration")
    provider_config = json.loads(resp.text)
    assert provider_config["issuer"] == server_url


def test_provider_static_files(server_url):
    resp = requests.get(server_url + "/.well-known/openid-configuration")
    provider_config = json.loads(resp.text)

    # try to fetch JWKS which is served by the webserver
    resp = requests.get(provider_config["jwks_uri"])
    assert "keys" in json.loads(resp.text)
