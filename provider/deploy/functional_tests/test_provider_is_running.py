# pylint: disable=missing-docstring

import json
from urllib.parse import urlparse

from oic.oic.message import RegistrationRequest, RegistrationResponse, AuthorizationRequest, \
    AuthorizationResponse, IdToken
import requests

from conftest import fill_login_details


def test_provider_is_reachable(server_url, provider_info):
    assert provider_info["issuer"] == server_url


def test_provider_static_files(provider_info):
    # try to fetch JWKS which is served by the webserver
    resp = requests.get(provider_info["jwks_uri"])
    assert "keys" in json.loads(resp.text)


def test_dynamic_client(provider_info, browser):
    redirect_uri = "http://localhost"
    # Dynamic registration
    reg_req = RegistrationRequest(**{"redirect_uris": [redirect_uri]})
    resp = requests.post(reg_req.request(provider_info["registration_endpoint"]))
    reg_resp = RegistrationResponse().from_json(resp.text)

    # Authentication
    auth_req = AuthorizationRequest(
        **{"client_id": reg_resp["client_id"], "scope": "openid", "response_type": "id_token",
           "redirect_uri": redirect_uri, "state": "state0", "nonce": "nonce0"})
    browser.get(auth_req.request(provider_info["authorization_endpoint"]))
    fill_login_details(browser)

    # Authentication response
    urlencoded_resp = urlparse(browser.current_url).fragment
    auth_resp = AuthorizationResponse().from_urlencoded(urlencoded_resp)
    idt = IdToken().from_jwt(auth_resp["id_token"], verify=False)
    assert browser.current_url.startswith(redirect_uri)
    assert auth_resp["state"] == "state0"
    assert idt["nonce"] == "nonce0"
