"""Mock internal service: internal-api (port 7003).

Trivial GET target. The service checkout-bot is legitimately scoped to reach.
No auth here — the broker is the only path in.
"""

from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/", defaults={"path": ""}, methods=["GET"])
@app.route("/<path:path>", methods=["GET"])
def serve(path):
    return jsonify({"service": "internal-api", "data": "order_status: ok"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=7003)
