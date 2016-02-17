import os

from oic.oauth2 import rndstr
from oic.oic import Client as OIDCClient
from oic.oic.message import AuthorizationResponse, RegistrationResponse
from oic.utils import time_util
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from .defaults import IMPLICIT_FLOW

__author__ = 'regu0004'


class Client(object):
    ROOT_PATH = "/Users/regu0004/dev/oidc_course/"
    ISSUER = "http://192.168.99.1:8000"

    def __init__(self, client_metadata):
        self.client = OIDCClient(client_authn_method=CLIENT_AUTHN_METHOD)

        self.provider_info = self.client.provider_config(Client.ISSUER)

        static = False
        extra_registration_params = {"userinfo_signed_response_alg": "RS256"}
        if static:
            reg_info = RegistrationResponse(**{"client_id": "TODO", "client_secret": "TODO"})
            self.client.store_registration_info(reg_info)
        else:
            if extra_registration_params:
                client_metadata.update(extra_registration_params)
            self.client.register(self.provider_info["registration_endpoint"], **client_metadata)

    def authenticate(self, session):
        request_args = IMPLICIT_FLOW

        session["state"] = rndstr()
        session["nonce"] = rndstr()

        request_args["state"] = session["state"]
        request_args["nonce"] = session["nonce"]

        auth_req = self.client.construct_AuthorizationRequest(request_args=request_args)
        login_url = auth_req.request(self.client.authorization_endpoint)

        return login_url

    def code_flow_callback(self, auth_response, session):
        auth_response = self.parse_authentication_response(auth_response)
        assert auth_response["state"] == session["state"]

        token_response = self.make_token_request(auth_response["code"], session["state"])
        self.validate_id_token(token_response["id_token"], session["nonce"])

        userinfo = self.make_userinfo_request(token_response["access_token"])

        return success_page(auth_response["code"], token_response["access_token"],
                            token_response["id_token"], userinfo)

    def implicit_flow_callback(self, auth_response, session):
        auth_response = self.parse_authentication_response(auth_response)
        assert auth_response["state"] == session["state"]

        self.validate_id_token(auth_response["id_token"], session["nonce"])

        access_code = auth_response.get("code")
        access_token = auth_response.get("access_token")

        return success_page(access_code, access_token, auth_response["id_token"], None)

    def parse_authentication_response(self, auth_response):
        auth_response = self.client.parse_response(AuthorizationResponse, info=auth_response,
                                                   sformat="urlencoded")
        return auth_response

    def make_token_request(self, auth_code, state):
        args = {
            "code": auth_code,
            "client_id": self.client.client_id,
            "client_secret": self.client.client_secret
        }

        token_response = self.client.do_access_token_request(scope="openid", state=state,
                                                             request_args=args)

        return token_response

    def make_userinfo_request(self, access_token):
        userinfo_response = self.client.do_user_info_request(access_token=access_token)
        return userinfo_response

    def validate_id_token(self, id_token, nonce):
        """http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation"""
        # see oic.Client.verify_id_token
        assert id_token["iss"] == self.client.provider_info["issuer"]
        assert self.client.client_id in id_token["aud"]
        if len(id_token["aud"]) > 1:
            assert "azp" in id_token and id_token["azp"] == self.client.client_id

        assert time_util.utc_time_sans_frac() < id_token["exp"]
        assert id_token["nonce"] == nonce


def success_page(auth_code, access_token, id_token_claims, userinfo):
    html_page = read_from_file("success_page.html")
    return html_page.format(auth_code, access_token, id_token_claims, userinfo)


def read_from_file(path):
    full_path = os.path.join(Client.ROOT_PATH, path)
    with open(full_path, "r") as f:
        return f.read()
