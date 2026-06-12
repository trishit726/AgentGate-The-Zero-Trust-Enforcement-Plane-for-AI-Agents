"""Issue the demo agent roster and write tokens to tokens/<agent>.jwt (gitignored).

The roster proves enforcement is policy, not a hardcode:
  - checkout-bot  : [internal-api]                          (the demo victim)
  - analytics-bot : [prod-db, internal-api]
  - ops-bot       : [prod-db, secrets-store, internal-api]  (CAN reach secrets-store —
                    shows the deny is about scope, not a blacklist on the service)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

from broker import identity  # noqa: E402 — load .env before importing (secret check)

ROSTER = {
    "checkout-bot": ["internal-api"],
    "analytics-bot": ["prod-db", "internal-api"],
    "ops-bot": ["prod-db", "secrets-store", "internal-api"],
}

TOKENS_DIR = "tokens"


def main():
    os.makedirs(TOKENS_DIR, exist_ok=True)
    for agent, scope in ROSTER.items():
        token = identity.issue_token(agent, scope, ttl_seconds=86400)
        path = os.path.join(TOKENS_DIR, f"{agent}.jwt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(token)
        print(f"issued {agent:14s} scope={scope} -> {path}")


if __name__ == "__main__":
    main()
