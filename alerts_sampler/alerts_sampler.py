from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from bson.objectid import ObjectId
import time
import datetime


class AlertsSampler:
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

    def get_alerts_to_sample(self):
        alert_to_sample = self._database["Alerts"].find({})
        alert_to_sample_list = list(alert_to_sample)

        type_arrays = {}
        for alert in alert_to_sample_list:
            alert_type = alert["type"]
            if alert_type not in type_arrays:
                type_arrays[alert_type] = []
            type_arrays[alert_type].append(alert)

        return type_arrays

    def fire_alert(self, value, alert_id):
        print(f'Firing Alert - alertID:{alert_id}, value: {value}')
        now = datetime.datetime.now()
        self._database["AlertsFired"].insert_one({"fired":True ,"alertID": ObjectId(alert_id), "value": value, "time": f'{now.hour}:{now.minute} - {now.day}/{now.month}'})

    def sample_bandwidth_usage_alerts(self, alerts):
        for alert in alerts:
            threshold = self.get_bandwidth_threshold(alert["property"])
            pipeline = self._database["BandwidthUsage"].aggregate([
                {
                    "$match": {
                        "$expr": {
                            "$gt": [{"$sum": ["$upload", "$download"]}, threshold]
                        }
                    }
                }
            ])
            matching_documents = list(pipeline)
            for doc in matching_documents:
                exisiting_alerts_amount = self._database["AlertsFired"].count_documents({"value": doc["ip"], "alertID": ObjectId(alert["_id"])})
                if exisiting_alerts_amount == 0:
                    self.fire_alert(doc["ip"], alert["_id"])

    @staticmethod
    def get_bandwidth_threshold(property):
        numeric_part = int(property[:-2])
        unit = property[-2:]

        if unit == "Kb":
            return numeric_part
        elif unit == "Mb":
            return numeric_part * 1000
        elif unit == "Gb":
            return numeric_part * 1000000

    def sample_new_endpoint_alerts(self, alerts):
        for alert in alerts:
            latest_alert = self._database["AlertsFired"].find({"alertID":ObjectId(alert["_id"])}).sort([("_id", -1)])
            latest_alert_list = list(latest_alert)
            new_endpoints = []
            if len(latest_alert_list) > 0:
                latest_alert_id = latest_alert_list[0]["_id"]
                new_endpoints = self._database["BandwidthUsage"].find({"_id":{"$gt": latest_alert_id}})
            else:
                new_endpoints = self._database["BandwidthUsage"].find()
            for endpoint in new_endpoints:
                self.fire_alert(endpoint["ip"], alert["_id"])

    def sample_access_alerts(self, alerts):
        for alert in alerts:
            latest_alert = self._database["AlertsFired"].find({"alertID":ObjectId(alert["_id"])}).sort([("_id", -1)])
            latest_alert_list = list(latest_alert)
            new_access = []
            if len(latest_alert_list) > 0:
                latest_alert_id = latest_alert_list[0]["_id"]
                new_access = self._database["TopDNS"].find({"lastModified":{"$gt": latest_alert_id}, "domain": f'{alert["property"].lower()}.com'})
            else:
                new_access = self._database["TopDNS"].find({"domain": f'{alert["property"].lower()}.com'})
            for access in new_access:
                self.fire_alert("-", alert["_id"])

    def sample(self):
        while True:
            print("Sampling Alerts")
            alerts_lists = self.get_alerts_to_sample()
            self.sample_new_endpoint_alerts(alerts_lists["New Endpoint"])
            self.sample_bandwidth_usage_alerts(alerts_lists["Usage Alert"])
            self.sample_access_alerts(alerts_lists["Access Alert"])
            time.sleep(15)



if __name__ == "__main__":
    sampler = AlertsSampler()
    sampler.connect()
    sampler.sample()
