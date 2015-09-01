import json
import urllib

import cherrypy
from oic.oauth2 import rndstr
from oic.oic import Client
from oic.oic.message import AuthorizationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.http_util import Redirect


__author__ = 'regu0004'


class OIDCExampleRP(object):
    def __init__(self, client_metadata, issuer_url):
        self.client = Client(client_authn_method=CLIENT_AUTHN_METHOD)

        with open(client_metadata) as f:
            self.client_metadata = json.load(f)

        # Choose the first (and only?) redirect URI
        self.redirect_uri = self.client_metadata["redirect_uris"][0]

        self.provider_info = self.client.provider_config(issuer_url)
        self.client.register(self.provider_info["registration_endpoint"], **self.client_metadata)

    def make_authentication_request(self, scope):
        self.last_state = rndstr()
        self.last_nonce = rndstr()
        request_args = {
            "response_type": "code",
            "scope": scope,
            "state": self.last_state,
            "nonce": self.last_nonce,
            "redirect_uri": self.redirect_uri
        }

        auth_req = self.client.construct_AuthorizationRequest(request_args=request_args)
        login_url = auth_req.request(self.client.authorization_endpoint)

        raise cherrypy.HTTPRedirect(login_url, 302)

    def parse_authentication_response(self, query_string):
        auth_response = self.client.parse_response(AuthorizationResponse, info=query_string, sformat="urlencoded")

        if auth_response["state"] != self.last_state:
            raise "The OIDC state does not match."

        return auth_response

    def make_token_request(self, auth_code):
        args = {
            "code": auth_code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client.client_id,
            "client_secret": self.client.client_secret
        }

        token_response = self.client.do_access_token_request(scope="openid", state=self.last_state, request_args=args)

        return token_response

    def make_userinfo_request(self, access_token):
        userinfo_response = self.client.do_user_info_request(access_token=access_token)
        return userinfo_response


class RPServer(object):
    def __init__(self):
        self.rp = OIDCExampleRP("../../client.json", "https://dirg.org.umu.se:8092")

    @cherrypy.expose
    def index(self):
        return "Python " + self._load_HTML_page_from_file("../../index.html")

    @cherrypy.expose
    def authenticate(self):
        redirect_url = self.rp.make_authentication_request("openid")
        raise cherrypy.HTTPRedirect(redirect_url, 302)

    @cherrypy.expose
    def repost_fragment(self, **kwargs):
        response = self.client.parse_response(AuthorizationResponse, info=kwargs["url_fragment"], sformat="urlencoded")

        html_page = self._load_HTML_page_from_file("../../success_page.html")
        return html_page.format(None, response["access_token"], response["id_token"], None)

    @cherrypy.expose
    def code_flow_callback(self, **kwargs):
        if "error" in kwargs:
            raise cherrypy.HTTPError(500, "{}: {}".format(kwargs["error"], kwargs["error_description"]))

        auth_code = self.rp.parse_authentication_response(cherrypy.request.query_string)["code"]
        token_response = self.rp.make_token_request(auth_code)
        userinfo = self.rp.make_userinfo_request(token_response["access_token"])

        html_page = self._load_HTML_page_from_file("../../success_page.html")
        return html_page.format(auth_code, token_response["access_token"], token_response["id_token"], userinfo)

    @cherrypy.expose
    def implicit_flow_callback(self, **kwargs):
        return self._load_HTML_page_from_file("../../repost_fragment.html")

    def _load_HTML_page_from_file(self, path):
        with open(path, "r") as f:
            return f.read()


def main():

    cherrypy.server.socket_host = "0.0.0.0"
    cherrypy.server.socket_port = 8090

    cherrypy.quickstart(RPServer())