"""Deploy AgentGate detections + dashboard to Splunk over REST (no restart needed).

    python scripts/deploy_splunk.py

Source of truth stays in the repo: parses splunk/savedsearches.conf and pushes each
stanza to saved/searches; wraps splunk/dashboard.json in a v2 (Dashboard Studio) view
and pushes it to data/ui/views as `agentgate_control`. Idempotent — re-running updates
in place. Credentials: SPLUNK_USERNAME / SPLUNK_PASSWORD in .env (admin on :8089).
"""

import configparser
import json
import os
import sys
from xml.sax.saxutils import escape

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests  # noqa: E402
import urllib3  # noqa: E402
from dotenv import load_dotenv  # noqa: E402

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_BASE = os.environ.get("SPLUNK_MGMT_URL", "https://localhost:8089")
_AUTH = (os.environ.get("SPLUNK_USERNAME", "admin"), os.environ.get("SPLUNK_PASSWORD", ""))
_NS = f"{_BASE}/servicesNS/{_AUTH[0]}/search"
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DASHBOARD_NAME = "agentgate_control"

# conf keys whose REST argument is spelled differently
_REST_KEY_MAP = {
    "enableSched": "is_scheduled",
    "counttype": "alert_type",
    "relation": "alert_comparator",
    "quantity": "alert_threshold",
}


def _post(url: str, data: dict) -> requests.Response:
    return requests.post(url, data=data, auth=_AUTH, verify=False, timeout=15)


def _upsert(collection_url: str, name: str, attrs: dict) -> str:
    """POST to create; on 409 POST to the entity to update. Returns 'created'/'updated'."""
    resp = _post(collection_url, {"name": name, **attrs})
    if resp.status_code in (200, 201):
        return "created"
    if resp.status_code == 409:
        resp = _post(f"{collection_url}/{requests.utils.quote(name, safe='')}", attrs)
        resp.raise_for_status()
        return "updated"
    raise RuntimeError(f"{name}: HTTP {resp.status_code} — {resp.text[:300]}")


def deploy_savedsearches() -> None:
    conf = configparser.RawConfigParser(strict=False)
    conf.optionxform = str  # preserve key case (alert.severity, dispatch.*)
    conf.read(os.path.join(_REPO, "splunk", "savedsearches.conf"), encoding="utf-8")

    for stanza in conf.sections():
        attrs = {_REST_KEY_MAP.get(k, k): v for k, v in conf.items(stanza)}
        outcome = _upsert(f"{_NS}/saved/searches", stanza, attrs)
        print(f"  saved search {outcome}: {stanza}")


def deploy_dashboard() -> None:
    path = os.path.join(_REPO, "splunk", "dashboard.json")
    with open(path, encoding="utf-8") as fh:
        definition = json.load(fh)  # validates JSON before pushing

    xml = (
        '<dashboard version="2" theme="dark">\n'
        f"  <label>{escape(definition['title'])}</label>\n"
        f"  <description>{escape(definition['description'])}</description>\n"
        f"  <definition><![CDATA[\n{json.dumps(definition, indent=2)}\n]]></definition>\n"
        "</dashboard>"
    )
    outcome = _upsert(f"{_NS}/data/ui/views", DASHBOARD_NAME, {"eai:data": xml})
    print(f"  dashboard {outcome}: {DASHBOARD_NAME} ({_BASE.replace('8089', '8000')}"
          f"/en-US/app/search/{DASHBOARD_NAME})")


def main() -> None:
    if not _AUTH[1]:
        sys.exit("SPLUNK_PASSWORD is unset in .env — cannot deploy")
    print(f"deploying to {_BASE} as {_AUTH[0]}")
    deploy_savedsearches()
    deploy_dashboard()
    print("done.")


if __name__ == "__main__":
    main()
