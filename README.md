# Policy Proxy

A Python HTTP forward proxy with configurable domain-based access control.

## Overview

Policy Proxy sits between an HTTP client and a destination server. It evaluates the destination hostname against configurable allow/deny rules, forwards permitted requests, and rejects blocked destinations.

This project explores HTTP networking, policy enforcement, error handling, concurrency, and automated testing.

## Features

- Exact and wildcard domain matching
- Case-insensitive hostname matching and trailing-dot normalization
- Default-deny policy evaluation
- Deny rules take precedence over allow rules
- Configurable rules loaded from `rules.txt`
- Destination hostname validation
- HTTP forwarding for GET, HEAD, POST, PUT, DELETE, and PATCH
- HTTP 403 responses for blocked destinations
- HTTP 400 responses for malformed or unsupported destination URLs
- HTTP 502 responses for upstream connection failures
- Upstream connection timeout configuration
- Request logging with destination, policy decision, and duration
- Threaded request handling
- Automated policy and proxy integration tests

## Requirements

- Python 3.10 or later
- pytest for running tests

## Setup

Clone the repository and enter its directory:

```bash
git clone https://github.com/fida22/policy-proxy.git
cd policy-proxy
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the test dependency:

```bash
python -m pip install -r requirements.txt
```

## Configure Access Rules

Edit `rules.txt`:

```text
allow example.com
allow *.wikipedia.org
allow 127.0.0.1
deny *.badsite.com
```

Rules are evaluated by destination hostname. Wildcard patterns match subdomains, not the base domain itself. Deny rules take precedence over allow rules, and destinations without a matching allow rule are denied.

The `allow 127.0.0.1` rule is included for local development and testing. Review access rules carefully before using the proxy in any other environment.

## Run the Proxy

Start the proxy:

```bash
python proxy.py
```

The proxy listens on:

```text
127.0.0.1:8080
```

Requests are evaluated against the configured rules before forwarding.

## Test with a Local HTTP Server

In a separate terminal, start a local HTTP server:

```bash
python3 -m http.server 8000 --bind 127.0.0.1
```

In another terminal, send a request through the proxy:

```bash
curl --noproxy "" -i \
  -x http://127.0.0.1:8080 \
  http://127.0.0.1:8000/
```

The local server should return `HTTP 200 OK` when the destination is allowed.

To test a blocked destination:

```bash
curl --noproxy "" -i \
  -x http://127.0.0.1:8080 \
  http://blocked.badsite.com/
```

The proxy should return `HTTP 403 Forbidden` without attempting an upstream connection.

Stop the local test server with `Ctrl+C` when finished.

## Run Automated Tests

Run the complete test suite:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -v
```

The environment variable disables automatic third-party pytest plugin loading, which avoids unrelated plugin issues in some development environments.

The test suite covers:

- Exact and wildcard domain matching
- Case-insensitive matching and trailing-dot normalization
- Allow/deny rules and default-deny behavior
- Rule validation and configuration loading
- Allowed HTTP request forwarding
- Blocked requests and policy enforcement
- Upstream connection failures
- Malformed destination URLs
- Simulated upstream timeout handling

The current test suite has 18 tests passing.

## Logging and Error Handling

The proxy logs the client address, destination hostname, policy decision, and request duration.

Expected HTTP responses include:

| Status | Meaning |
|---|---|
| `200 OK` | Successful response from an upstream server |
| `400 Bad Request` | Invalid or unsupported destination URL |
| `403 Forbidden` | Destination blocked by policy |
| `501 Not Implemented` | Unsupported request functionality, including HTTPS CONNECT |
| `502 Bad Gateway` | Upstream connection or request failure |

## Current Limitations

- HTTPS `CONNECT` tunneling is not implemented.
- Chunked request bodies are rejected.
- Request bodies are limited to 10 MB.
- HTTP protocol compatibility and edge cases require further testing.
- The implementation is a learning project, not a production-grade security proxy.
- It does not provide TLS inspection, user authentication, a dashboard, or enterprise security controls.
- Performance has only been checked with a basic test of ten concurrent requests; no formal benchmark has been completed.

## Future Improvements

- HTTPS `CONNECT` tunneling
- More extensive timeout and malformed-request testing
- Performance benchmarks and larger concurrency tests
- Improved HTTP protocol compatibility
- More configurable runtime settings
- Continuous integration for automated tests