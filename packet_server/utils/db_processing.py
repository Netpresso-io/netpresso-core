from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from bson.objectid import ObjectId
import pymongo
import bson.json_util as json_utils


class DBUtils:

    def __init__(self):
        self._connection_string = "mongodb+srv://user:TY1VocdoRt1Fgoui@cluster0.9x7j3hh.mongodb.net/?retryWrites=true&w=majority"
        self._client = MongoClient(self._connection_string, server_api=ServerApi('1'))
        self._database = self._client["Netpresso"]

    def connect(self):
        try:
            self._client.admin.command('ping')
            print("Pinged your deployment. You successfully connected to MongoDB!")
        except Exception as e:
            print(e)


    def get_top_dns(self):
        projection = {"_id":0, "domain":1, "amount":1}
        top_dns = self._database["TopDNS"].find({}, projection).sort("amount", pymongo.DESCENDING).limit(5)
        top_dns_list = list(top_dns)
        top_dns_json = json_utils.dumps(top_dns_list, indent=4)
        return top_dns_json


    def get_bandwidth_usage(self):
        projection = {"_id":0, "ip":1, "download":1, "upload":1}
        bandwidth_usage = self._database["BandwidthUsage"].find({}, projection)
        bandwidth_usage_list = list(bandwidth_usage)
        bandwidth_usage_json = json_utils.dumps(bandwidth_usage_list, indent=4)
        return bandwidth_usage_json

    def get_fired_alerts(self):
        pipeline = [
            {
                "$lookup": {
                    "from": "Alerts",
                    "localField": "alertID",
                    "foreignField": "_id",
                    "as": "alert_type"
                }
            },
            {
                "$unwind": "$alert_type"
            },
            {
                "$set":{
                    "type": "$alert_type.type",
                    "property": "$alert_type.property"
                }
            },
            {
                "$unset": "alert_type"
            },
            {
                "$project": {
                    "_id":1,
                    "alert_type._id":0,
                    "alertID": 0,
                    "alert_type_prefix":0,
                }
            }
        ]
        result = list(self._database["AlertsFired"].aggregate(pipeline))
        return json_utils.dumps(result)

    def get_alerts(self):
        projection = {"_id":1, "type":1, "property":1}
        alerts = self._database["Alerts"].find({}, projection)
        alerts_list = list(alerts)
        alerts_list_json = json_utils.dumps(alerts_list, indent=4)
        return alerts_list_json

    def add_alert(self, alert):
        self._database["Alerts"].insert_one({"type": alert["type"], "property": alert["property"]})
        return "Success"

    def resolve_alert(self, alert_id):
        print(alert_id)
        res = self._database["AlertsFired"].find_one({"_id":ObjectId(alert_id)})
        print(res)
        result = self._database["AlertsFired"].update_one({"_id":ObjectId(alert_id)}, {"$set": {"fired": False}})
        print(result.raw_result)
        res = self._database["AlertsFired"].find_one({"_id":ObjectId(alert_id)})
        print(res)
        return "Success"

