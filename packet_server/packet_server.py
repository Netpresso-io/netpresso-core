from flask import Flask, request
from utils.packet_processing import PacketUtils

app = Flask(__name__)


@app.route("/top-dns")
def home():
    return PacketUtils.get_top_dns(request.args.get("file_name"))


if __name__ == "__main__":
    app.run(debug=True, port=3000)
