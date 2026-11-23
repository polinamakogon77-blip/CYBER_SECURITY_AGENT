"""Optional tool registration for the existing LangGraph agent."""

import json

from langchain.tools import tool

from .file_inclusion_probe import scan_lab


@tool
def check_file_inclusion(base_url: str, remote_payload_url: str,
                         lfi_endpoint: str = "/api/lfi",
                         rfi_endpoint: str = "/api/rfi") -> str:
    """Test LFI and RFI on the authorized Python file-inclusion classroom lab.

    Uses only dummy local and remote modules. remote_payload_url must point to
    the lab's /payload.py fixture and be reachable from the target itself.
    Returns JSON with separate LFI/RFI evidence and statuses. A 200 response or
    error alone never confirms inclusion. Use the -safe endpoints as controls.
    """
    try:
        report = scan_lab(base_url, remote_payload_url, lfi_endpoint, rfi_endpoint)
    except ValueError as exc:
        return json.dumps({"error": str(exc)}, ensure_ascii=False)
    return json.dumps(report, ensure_ascii=False, indent=2)
