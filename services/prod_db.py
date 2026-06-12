"""Mock internal service: prod-db (port 7001).

Trivial GET target. Its only job is to be a service the broker allows or refuses.
There is no auth here — in the demo the broker is the only path in.
"""

from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/", defaults={"path": ""}, methods=["GET"])
@app.route("/<path:path>", methods=["GET"])
def serve(path):
    return jsonify({"service": "prod-db", "data": "customer_records_v2"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=7001)
