# Policy Proxy

A Python project exploring HTTP proxying and domain-based access control.

## Overview

Policy Proxy is designed to sit between a client and an HTTP destination, evaluate the destination hostname against configurable access rules, and either forward the request or reject it.

## Implemented

- Exact and wildcard domain matching
- Case-insensitive hostname matching and trailing-dot normalization
- Default-deny policy evaluation
- Deny rules take precedence over allow rules
- Loading allow/deny rules from a configuration file
- Basic domain-pattern validation
- Automated unit tests for policy behavior

## Example Rules

```text
allow example.com
allow *.wikipedia.org
deny *.badsite.com
```

## Setup

Requires Python 3.10 or later.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pytest
```

## Run Tests

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -v
```

The environment variable disables automatic third-party pytest plugin loading, which avoids unrelated ROS 2 plugin errors in the development environment.

## Planned Features

- Local HTTP proxy listener
- HTTP request parsing and destination extraction
- Domain-policy enforcement before forwarding
- HTTP 403 responses for blocked destinations
- Forwarding allowed HTTP requests
- Access logging, timeouts, and error handling
- Concurrent connection handling
- Integration tests and performance measurements

HTTPS CONNECT tunneling is a possible extension.

## Limitations

The current implementation covers the domain policy engine, not a complete HTTP proxy. Planned features will be documented as implemented only after they have been tested.

This project is intended for local development and learning, not production security enforcement.