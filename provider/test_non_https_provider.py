import os

from oic.oic.message import RegistrationRequest, RegistrationResponse
from oic.utils import shelve_wrapper

from server import NonHttpsProvider


def test_registration(tmpdir):
    client_db_path = os.path.join(tmpdir.strpath, "client_db")
    cdb = shelve_wrapper.open(client_db_path)
    provider = NonHttpsProvider("testprovider", None, cdb, None, None, None,
                                None, None)

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
