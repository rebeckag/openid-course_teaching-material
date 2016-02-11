#!/usr/bin/env python

import json
import logging
import sys
import traceback
from urllib.parse import parse_qs, urlparse
import re
import os

import yaml
from mako.lookup import TemplateLookup
from oic.oauth2 import rndstr
from oic.utils import shelve_wrapper
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import UsernamePasswordMako
from oic.utils.authz import AuthzHandling
from oic.utils.http_util import wsgi_wrapper, BadRequest, ServiceError, Response
from oic.utils.keyio import keyjar_init
from oic.utils.userinfo import UserInfo
from oic.utils.webfinger import WebFinger
from oic.utils.webfinger import OIC_ISSUER
from oic.utils.authn.authn_context import AuthnBroker, make_auth_verify
from oic.utils.sdb import SessionDB
from oic.oic.provider import AuthorizationEndpoint
from oic.oic.provider import TokenEndpoint
from oic.oic.provider import UserinfoEndpoint
from oic.oic.provider import RegistrationEndpoint
from course_provider import CourseProvider

LOGGER = logging.getLogger("")
LOGFILE_NAME = 'oc.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

CPC = ('%(asctime)s %(name)s:%(levelname)s '
       '[%(client)s,%(path)s,%(cid)s] %(message)s')
cpc_formatter = logging.Formatter(CPC)

hdlr.setFormatter(base_formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.DEBUG)

PASSWD = {
    "diana": "krall",
    "babs": "howes",
    "upper": "crust"
}

ENDPOINTS = [
    AuthorizationEndpoint(),
    TokenEndpoint(),
    UserinfoEndpoint(),
    RegistrationEndpoint(),
]


def add_endpoints(endpoints, endpoint_functions):
    global URLS

    for endp, func in zip(endpoints, endpoint_functions):
        URLS.append(("^%s" % endp.etype, func))


ROOT = './'

LOOKUP = TemplateLookup(directories=['templates'], input_encoding='utf-8',
                        output_encoding='utf-8')


# noinspection PyUnusedLocal
def token(environ, start_response, logger):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.token_endpoint,
                        logger=logger)


# noinspection PyUnusedLocal
def authorization(environ, start_response, logger):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.authorization_endpoint,
                        logger=logger)


# noinspection PyUnusedLocal
def userinfo(environ, start_response, logger):
    _oas = environ["oic.oas"]

    return wsgi_wrapper(environ, start_response, _oas.userinfo_endpoint,
                        logger=logger)


# noinspection PyUnusedLocal
def op_info(environ, start_response, logger):
    _oas = environ["oic.oas"]
    LOGGER.info("op_info")
    return wsgi_wrapper(environ, start_response, _oas.providerinfo_endpoint,
                        logger=logger)


# noinspection PyUnusedLocal
def registration(environ, start_response, logger):
    _oas = environ["oic.oas"]

    if environ["REQUEST_METHOD"] == "POST":
        return wsgi_wrapper(environ, start_response, _oas.registration_endpoint,
                            logger=logger)
    elif environ["REQUEST_METHOD"] == "GET":
        return wsgi_wrapper(environ, start_response, _oas.read_registration,
                            logger=logger)
    else:
        resp = ServiceError("Method not supported")
        return resp(environ, start_response)


def webfinger(environ, start_response, _):
    query = parse_qs(environ["QUERY_STRING"])
    try:
        assert query["rel"] == [OIC_ISSUER]
        resource = query["resource"][0]
    except KeyError:
        resp = BadRequest("Missing parameter in request")
    else:
        wf = WebFinger()
        resp = Response(wf.response(subject=resource, base=OAS.baseurl))
    return resp(environ, start_response)


ENDPOINT_FUNCS = [
    authorization,
    token,
    userinfo,
    registration
]

URLS = [
    (r'^.well-known/openid-configuration', op_info),
    (r'^.well-known/webfinger', webfinger),
]


def application(environ, start_response):
    """
    The main WSGI application. Dispatch the current request to
    the functions from above and store the regular expression
    captures in the WSGI environment as  `oic.url_args` so that
    the functions from above can access the url placeholders.

    If nothing matches call the `not_found` function.

    :param environ: The HTTP application environment
    :param start_response: The application to run when the handling of the
        request is done
    :return: The response as a list of lines
    """
    global OAS

    # user = environ.get("REMOTE_USER", "")
    path = environ.get('PATH_INFO', '').lstrip('/')

    logger = logging.getLogger('oicServer')

    environ["oic.oas"] = OAS

    for regex, callback in URLS:
        match = re.search(regex, path)
        if match is not None:
            try:
                environ['oic.url_args'] = match.groups()[0]
            except IndexError:
                environ['oic.url_args'] = path

            logger.info("callback: %s" % callback)
            try:
                return callback(environ, start_response, logger)
            except Exception as err:
                print(str(err), file=sys.stderr)
                message = traceback.format_exception(*sys.exc_info())
                print(message, file=sys.stderr)
                logger.exception("%s" % err)
                resp = ServiceError("%s" % err)
                return resp(environ, start_response)

    resp = Response(template_lookup=LOOKUP, mako_template="index.html")
    return resp(environ, start_response)


def bytes_middleware(application):
    def response_as_bytes(environ, start_response):
        resp = application(environ, start_response)

        # encode the data if necessary
        data = resp[0]
        if isinstance(data, str):
            data = data.encode("utf-8")
        return [data]

    return response_as_bytes


def setup():
    with open("config.yaml", 'r') as f:
        config = yaml.load(f)

    issuer = config["baseurl"]

    ac = AuthnBroker()

    authn = UsernamePasswordMako(
        None, "login.mako", LOOKUP, PASSWD, "{}/authorization".format(issuer))
    ac.add("password", authn)
    URLS.append((r'^verify', make_auth_verify(authn.verify)))

    authz = AuthzHandling()
    client_db_path = os.environ.get("OIDC_CLIENT_DB", "client_db")
    LOGGER.info("Using db: {}".format(client_db_path))
    cdb = shelve_wrapper.open(client_db_path)
    global OAS
    OAS = CourseProvider(issuer, SessionDB(issuer), cdb, ac, None,
                         authz, verify_client, rndstr(16))
    OAS.baseurl = issuer
    OAS.userinfo = UserInfo(config["userdb"])
    # Additional endpoints the OpenID Connect Provider should answer on
    add_endpoints(ENDPOINTS, ENDPOINT_FUNCS)
    OAS.endpoints = ENDPOINTS

    authn.srv = OAS

    try:
        OAS.cookie_ttl = config["cookie_ttl"]
    except KeyError:
        pass

    try:
        OAS.cookie_name = config["cookie_name"]
    except KeyError:
        pass

    keyjar_init(OAS, config["keys"])
    public_keys = []
    for keybundle in OAS.keyjar[""]:
        for key in keybundle.keys():
            public_keys.append(key.serialize())
    public_jwks = {"keys": public_keys}
    filename = "static/jwks.json"
    with open(filename, "w") as f:
        f.write(json.dumps(public_jwks))
    OAS.jwks_uri = "{}/{}".format(OAS.baseurl, filename)

    return config


config = setup()
wsgi = bytes_middleware(application)

if __name__ == "__main__":
    from wsgiref.simple_server import make_server
    from werkzeug.wsgi import SharedDataMiddleware

    app = SharedDataMiddleware(wsgi, {
        '/static': os.path.join(os.path.dirname(__file__), 'static')
    })

    host = urlparse(config["baseurl"]).netloc
    port = int(host.split(":", 1)[1])

    httpd = make_server('', port, app)
    print("Serving HTTP on port {}...".format(port))

    # Respond to requests until process is killed
    httpd.serve_forever()
