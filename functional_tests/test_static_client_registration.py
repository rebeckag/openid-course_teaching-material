from urllib.parse import urlparse

from oic.oic.message import AuthorizationRequest, AuthorizationResponse, IdToken


def test_service_adds_trailing_slash(server_url, browser):
    client_reg_url = server_url + "/client_registration"
    browser.get(client_reg_url)
    assert browser.current_url == client_reg_url + "/"


def test_static_client_registration(server_url, provider_info, browser):
    redirect_uri = "http://localhost:8090"
    browser.get(server_url + "/client_registration")
    new_url_input = browser.find_element_by_xpath("/html/body/div/div/div[1]/div[1]/form/div/input")
    new_url_input.send_keys(redirect_uri)
    add_btn = browser.find_element_by_xpath("/html/body/div/div/div[1]/div[1]/form/div/span/button")
    add_btn.click()

    submit_btn = browser.find_element_by_xpath("/html/body/div/div/div[2]/button")
    submit_btn.click()

    client_credentials = get_client_credentials_from_page(browser)

    args = {
        "client_id": client_credentials["client_id"],
        "scope": "openid",
        "response_type": "id_token",
        "redirect_uri": redirect_uri,
        "state": "state0",
        "nonce": "nonce0"
    }
    auth_req = AuthorizationRequest(**args)
    request = auth_req.request(provider_info["authorization_endpoint"])
    browser.get(request)

    browser.find_element_by_name("login").send_keys("diana")
    browser.find_element_by_name("password").send_keys("krall")
    browser.find_element_by_name("form.commit").click()

    urlencoded_resp = urlparse(browser.current_url).fragment
    auth_resp = AuthorizationResponse().from_urlencoded(urlencoded_resp)
    idt = IdToken().from_jwt(auth_resp["id_token"], verify=False)
    assert browser.current_url.startswith(redirect_uri)
    assert auth_resp["state"] == "state0"
    assert idt["nonce"] == "nonce0"


def get_client_credentials_from_page(browser):
    list = browser.find_element_by_xpath("/html/body/div[1]/ul")
    client_credentials = {}
    for element in list.find_elements_by_tag_name("li"):
        try:
            key, value = element.text.split(": ", 1)
            client_credentials[key] = value
        except ValueError:
            pass  # ignore row not containing colon-separated key-value pair

    return client_credentials
