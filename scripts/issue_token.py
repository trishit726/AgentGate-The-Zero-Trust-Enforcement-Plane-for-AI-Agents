"""Issue one scoped agent token and print it to stdout.

    python scripts/issue_token.py --agent checkout-bot --scope internal-api
    python scripts/issue_token.py --agent ops-bot --scope prod-db --scope secrets-store
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

from broker import identity  # noqa: E402 — must load .env before importing (secret check)


def main():
    parser = argparse.ArgumentParser(description="Issue a scoped AgentGate identity token.")
    parser.add_argument("--agent", required=True, help="agent_id, e.g. checkout-bot")
    parser.add_argument(
        "--scope",
        action="append",
        default=[],
        help="service the agent may reach; repeat for multiple",
    )
    parser.add_argument("--ttl", type=int, default=3600, help="token lifetime in seconds")
    args = parser.parse_args()

    token = identity.issue_token(args.agent, args.scope, args.ttl)
    print(token)


if __name__ == "__main__":
    main()
