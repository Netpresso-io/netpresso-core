from flask import Flask, request
from utils.db_processing import DBUtils
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DBUtilsInstance = DBUtils()

@app.route("/top-dns", methods=["GET"])
def top_dns():
    return DBUtilsInstance.get_top_dns()


@app.route("/bandwidth-usage", methods=["GET"])
def bandwidth_usage():
    return DBUtilsInstance.get_bandwidth_usage()


@app.route("/get-alerts", methods=["GET"])
def get_alerts():
    return DBUtilsInstance.get_alerts()


@app.route("/get-fired-alerts", methods=["GET"])
def get_fired_alerts():
    return DBUtilsInstance.get_fired_alerts()


@app.route("/add-alert", methods=["POST"])
def add_alert():
    new_alert = request.get_json()
    return DBUtilsInstance.add_alert(new_alert)


@app.route("/resolve-alert", methods=["POST"])
def resolve_alert():
    body = request.get_json()
    return DBUtilsInstance.resolve_alert(body["alert_id"])


  
if __name__ == "__main__":
    DBUtilsInstance.connect()
    app.run(debug=True, port=5000)
