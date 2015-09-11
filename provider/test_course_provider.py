# pylint: disable=missing-docstring
import os
import time

from oic.oic.message import RegistrationRequest, RegistrationResponse, AuthorizationRequest, \
    AuthorizationResponse, UserInfoRequest
from oic.utils import shelve_wrapper
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authz import AuthzHandling
from oic.utils.sdb import SessionDB
from oic.utils.userinfo import UserInfo
import pytest

from provider.course_provider import CourseProvider


class DummyAuthn(object):
    def authenticated_as(*args, **kwargs):
        return {"uid": "user"}, time.time()

    def create_cookie(self):
        return None


@pytest.fixture
def provider(tmpdir):
    client_db_path = os.path.join(tmpdir.strpath, "client_db")
    cdb = shelve_wrapper.open(client_db_path)

    ab = AuthnBroker()
    ab.add("dummy", DummyAuthn())

    sdb = SessionDB("https://testprovider.com")

    provider = CourseProvider("https://testprovider.com", sdb, cdb, ab, UserInfo({"user": {}}),
                              AuthzHandling(), None, None)
    return provider


def test_registration_with_non_https(provider):
    redirect_uris = ["http://example.org"]
    registration_params = {
        "application_type": "web",
        "response_types": ["id_token", "token"],
        "redirect_uris": redirect_uris}
    req = RegistrationRequest(**registration_params)
    resp = provider.registration_endpoint(req.to_urlencoded())

    resp = RegistrationResponse().from_json(resp.message)
    assert resp["client_id"] is not None
    assert resp["client_secret"] is not None
    assert resp["redirect_uris"] == redirect_uris


def test_scope_who_am_i(provider):
    registration_params = {
        "application_type": "web",
        "response_types": ["code", "token"],
        "redirect_uris": "http://example.org"}
    reg_req = RegistrationRequest(**registration_params)
    resp = provider.registration_endpoint(reg_req.to_urlencoded())
    reg_resp = RegistrationResponse().from_json(resp.message)

    auth_req = AuthorizationRequest(
        **{"client_id": reg_resp["client_id"], "scope": "openid who_am_i",
           "response_type": "code token",
           "redirect_uri": "http://example.org", "state": "state0", "nonce": "nonce0"})
    resp = provider.authorization_endpoint(auth_req.to_urlencoded())
    auth_resp = AuthorizationResponse().from_urlencoded(resp.message)

    userinfo_req = UserInfoRequest(**{"access_token": auth_resp["access_token"]})
    resp = provider.userinfo_endpoint(userinfo_req.to_urlencoded())
    userinfo_resp = AuthorizationResponse().from_json(resp.message)

    assert userinfo_resp["given_name"] == "Bruce"
    assert userinfo_resp["family_name"] == "Lee"
