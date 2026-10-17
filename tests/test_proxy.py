import socket
import threading
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from policy import load_rules
from proxy import ProxyHandler


class UpstreamHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"upstream-ok"

        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


@pytest.fixture
def proxy_server(tmp_path):
    rules_file = tmp_path / "rules.txt"
    rules_file.write_text(
        "allow 127.0.0.1\n"
        "deny *.badsite.com\n"
    )

    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        ProxyHandler,
    )
    server.rules = load_rules(str(rules_file))

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()

    yield server

    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


@pytest.fixture
def upstream_server():
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        UpstreamHandler,
    )

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()

    yield server

    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def make_proxy_request(proxy_server, url):
    connection = HTTPConnection(
        "127.0.0.1",
        proxy_server.server_address[1],
        timeout=5,
    )

    try:
        connection.request("GET", url)
        response = connection.getresponse()

        return response.status, response.read()
    finally:
        connection.close()


def test_allowed_request_is_forwarded(
    proxy_server,
    upstream_server,
):
    upstream_port = upstream_server.server_address[1]
    url = f"http://127.0.0.1:{upstream_port}/test"

    status, body = make_proxy_request(proxy_server, url)

    assert status == 200
    assert body == b"upstream-ok"


def test_blocked_request_returns_403(proxy_server, monkeypatch):
    import proxy

    def unexpected_upstream_connection(*args, **kwargs):
        pytest.fail("Blocked request attempted an upstream connection")

    monkeypatch.setattr(
        proxy,
        "HTTPConnection",
        unexpected_upstream_connection,
    )

    url = "http://blocked.badsite.com/test"
    status, body = make_proxy_request(proxy_server, url)

    assert status == 403
    assert b"Blocked by domain policy" in body


def test_upstream_failure_returns_502(proxy_server):
    # Reserve an ephemeral port, then release it so no server
    # should be listening there.
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        unused_port = sock.getsockname()[1]

    url = f"http://127.0.0.1:{unused_port}/test"

    status, body = make_proxy_request(proxy_server, url)

    assert status == 502
    assert b"Upstream request failed" in body
def test_relative_url_returns_400(proxy_server):
    status, body = make_proxy_request(
        proxy_server,
        "/relative/path",
    )

    assert status == 400
    assert b"Expected an absolute HTTP URL" in body
def test_upstream_timeout_returns_502(proxy_server, monkeypatch):
    import proxy

    class TimedOutConnection:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            raise TimeoutError("simulated upstream timeout")

        def close(self):
            pass

    monkeypatch.setattr(proxy, "HTTPConnection", TimedOutConnection)

    status, body = make_proxy_request(
        proxy_server,
        "http://127.0.0.1:8000/slow",
    )

    assert status == 502
    assert b"Upstream request failed" in body