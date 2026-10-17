
import logging
import time
from http.client import HTTPConnection, HTTPException
from urllib.parse import urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from policy import is_allowed, load_rules, validate_domain_pattern


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
)


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        self.forward_request()

    def do_HEAD(self):
        self.forward_request()

    def do_POST(self):
        self.forward_request()

    def do_PUT(self):
        self.forward_request()

    def do_DELETE(self):
        self.forward_request()

    def do_PATCH(self):
        self.forward_request()

    def do_CONNECT(self):
        self.send_error(
            501,
            "HTTPS CONNECT tunneling is not implemented",
        )

    def forward_request(self):
        started = time.monotonic()
        host = "-"
        decision = "ERROR"
        upstream = None

        try:
            # A forward proxy normally receives an absolute URL.
            url = urlsplit(self.path)

            if url.scheme.lower() != "http" or not url.hostname:
                self.send_error(
                    400,
                    "Expected an absolute HTTP URL",
                )
                return

            if url.username or url.password:
                self.send_error(400, "URL credentials are unsupported")
                return

            host = url.hostname.lower().rstrip(".")

            try:
                validate_domain_pattern(host)
            except ValueError:
                self.send_error(400, "Invalid destination hostname")
                return

            # Keep this first version simple: reject chunked request bodies.
            if self.headers.get("Transfer-Encoding"):
                self.send_error(
                    501,
                    "Transfer-encoded request bodies are unsupported",
                )
                return

            if not is_allowed(host, self.server.rules):
                decision = "BLOCKED"
                self.send_error(403, "Blocked by domain policy")
                return

            decision = "ALLOWED"

            port = url.port or 80
            target = url.path or "/"

            if url.query:
                target += "?" + url.query

            # Read a request body only when Content-Length is provided.
            length_text = self.headers.get("Content-Length", "0")

            try:
                length = int(length_text)
                if length < 0 or length > 10_000_000:
                    raise ValueError
            except ValueError:
                self.send_error(400, "Invalid Content-Length")
                return

            body = self.rfile.read(length) if length else None

            # Remove hop-by-hop headers before forwarding.
            hop_by_hop = {
                "connection",
                "proxy-connection",
                "keep-alive",
                "te",
                "trailer",
                "transfer-encoding",
                "upgrade",
                "host",
            }

            headers = {
                name: value
                for name, value in self.headers.items()
                if name.lower() not in hop_by_hop
            }

            headers["Host"] = url.netloc
            headers["Connection"] = "close"

            upstream = HTTPConnection(
                host,
                port,
                timeout=5,
            )

            upstream.request(
                self.command,
                target,
                body=body,
                headers=headers,
            )

            response = upstream.getresponse()

            self.send_response(response.status, response.reason)

            for name, value in response.getheaders():
                if name.lower() not in hop_by_hop:
                    self.send_header(name, value)

            self.send_header("Connection", "close")
            self.end_headers()

            # Stream the upstream response instead of loading it all at once.
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)

        except (OSError, HTTPException, ValueError) as exc:
            logging.warning("Proxy error for %s: %s", host, exc)

            # Do not attempt a second response after headers were sent.
            if not self.wfile.closed:
                try:
                    self.send_error(502, "Upstream request failed")
                except (OSError, ValueError):
                    pass

        finally:
            if upstream is not None:
                upstream.close()

            elapsed = time.monotonic() - started
            logging.info(
                "client=%s host=%s decision=%s duration=%.3fs",
                self.client_address[0],
                host,
                decision,
                elapsed,
            )


def main():
    rules = load_rules("rules.txt")

    server = ThreadingHTTPServer(
        ("127.0.0.1", 8080),
        ProxyHandler,
    )
    server.rules = rules
    server.timeout = 5

    logging.info("Policy Proxy listening on 127.0.0.1:8080")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down proxy")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
