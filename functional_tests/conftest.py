# pylint: disable=missing-docstring
import json
from urllib.parse import urlparse

import pytest
import requests
from selenium import webdriver


@pytest.yield_fixture
def browser():
    b = webdriver.PhantomJS()
    yield b
    b.quit()


def pytest_addoption(parser):
    parser.addoption("--url", action="store", default="localhost:8000",
                     help="url for the server where the services are hosted")


@pytest.fixture(scope="session")
def server_url(request):
    url = request.config.getoption("--url")
    if not urlparse(url).scheme:
        url = "http://" + url
    return url


@pytest.fixture(scope="session")
def provider_info(server_url):
    resp = requests.get(server_url + "/.well-known/openid-configuration")
    return resp.json()
