from oic.oic.message import ClaimsRequest, Claims

CODE_FLOW = {
    "redirect_uri": "http://localhost:8090/code_flow_callback",
    "scope": "openid",
    "response_type": "code"
}

IMPLICIT_FLOW = {
    "redirect_uri": "http://localhost:8090/implicit_flow_callback",
    "scope": "openid",
    "response_type": "id_token token"
}

HYBRID_FLOW = {
    "redirect_uri": "http://localhost:8090/implicit_flow_callback",
    "scope": "openid",
    "response_type": "code id_token"
}

CLAIMS_BY_SCOPE = {

    "redirect_uri": "http://localhost:8090/code_flow_callback",
    "scope": "openid profile",
    "response_type": "code"
}

CLAIMS_REQUEST = {
    "redirect_uri": "http://localhost:8090/code_flow_callback",
    "scope": "openid",
    "response_type": "code",
    "claims": ClaimsRequest(
        id_token=Claims(email={"essential": None}, phone_number=None),
        userinfo=Claims(given_name={"essential": True}, family_name={"essential": True},
                        nickname=None)
    )
}

SCOPE_BEHAVIOR = {
    "redirect_uri": "http://localhost:8090/code_flow_callback",
    "scope": "openid who_am_i",
    "response_type": "code"
}
