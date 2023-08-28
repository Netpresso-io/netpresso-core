from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import pymongo
import json


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
        top_dns_json = json.dumps(top_dns_list, indent=4)
        return top_dns_json


    def get_bandwidth_usage(self):
        projection = {"_id":0, "ip":1, "download":1, "upload":1}
        bandwidth_usage = self._database["BandwidthUsage"].find({}, projection)
        bandwidth_usage_list = list(bandwidth_usage)
        bandwidth_usage_json = json.dumps(bandwidth_usage_list, indent=4)
        return bandwidth_usage_json
