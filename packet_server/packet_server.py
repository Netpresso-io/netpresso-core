from flask import Flask, request
from utils.packet_processing import PacketUtils
from utils.db_processing import DBUtils
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DBUtilsInstance = DBUtils()

@app.route("/top-dns")
def top_dns():
    return DBUtilsInstance.get_top_dns()
    # packet_amount = request.args.get("packet_amount")
    # if packet_amount is None:
    #     packet_amount = 7500
    # return PacketUtils.get_top_dns(request.args.get("file_name"), int(packet_amount))


@app.route("/bandwidth-usage")
def bandwidth_usage():
    return DBUtilsInstance.get_bandwidth_usage()
    # packet_amount = request.args.get("packet_amount")
    # if packet_amount is None:
    #     packet_amount = 7500
    # return PacketUtils.get_bandwidth_usage(request.args.get("file_name"), int(packet_amount))
  
  
if __name__ == "__main__":
    DBUtilsInstance.connect()
    app.run(debug=True, port=5000)
