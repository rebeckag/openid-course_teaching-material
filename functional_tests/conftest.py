# content of conftest.py
from urllib.parse import urlparse
import pytest


def pytest_addoption(parser):
    parser.addoption("--url", action="store", default="localhost:8000",
                     help="url for the server where the services are hosted")


@pytest.fixture
def server_url(request):
    url = request.config.getoption("--url")
    if not urlparse(url).scheme:
        url = "http://" + url
    return url
