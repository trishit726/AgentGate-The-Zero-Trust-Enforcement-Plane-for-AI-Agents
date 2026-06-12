"""Mock internal service: secrets-store (port 7002).

Trivial GET target. The high-value service the prompt-injected agent tries to reach
and the broker refuses. No auth here — the broker is the only path in.
"""

from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/", defaults={"path": ""}, methods=["GET"])
@app.route("/<path:path>", methods=["GET"])
def serve(path):
    return jsonify({"service": "secrets-store", "data": "aws_keys, db_credentials"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=7002)
