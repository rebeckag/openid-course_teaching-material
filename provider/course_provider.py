from urllib.parse import urlparse, splitquery, parse_qs

from oic.oic.provider import Provider, InvalidRedirectURIError


class CourseProvider(Provider):
    """ Supports some special features:
            - doesn't enforce https scheme in redirect_uris
            - special behavior for the scope value 'who_am_i'
    """

    def _verify_redirect_uris(self, registration_request):
        verified_redirect_uris = []
        must_https = False  # don't verify https!

        for uri in registration_request["redirect_uris"]:
            p = urlparse(uri)
            if registration_request["application_type"] == "native" and p.scheme == "http":
                if p.hostname != "localhost":
                    raise InvalidRedirectURIError(
                        "Http redirect_uri must use localhost")
            elif must_https and p.scheme != "https":
                raise InvalidRedirectURIError(
                    "None https redirect_uri not allowed")
            elif p.fragment:
                raise InvalidRedirectURIError(
                    "redirect_uri contains fragment")

            base, query = splitquery(uri)
            if query:
                verified_redirect_uris.append((base, parse_qs(query)))
            else:
                verified_redirect_uris.append((base, query))

        return verified_redirect_uris

    def _collect_user_info(self, session, userinfo_claims=None):
        userinfo = super()._collect_user_info(session, userinfo_claims)
        # override some attributes
        if "who_am_i" in session['scope']:
            userinfo["given_name"] = "Bruce"
            userinfo["family_name"] = "Lee"
        return userinfo
