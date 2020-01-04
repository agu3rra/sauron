from pymongo import MongoClient
import json
from bson import json_util

MONGO_HOST = 'mongo'
MONGO_PORT = 27017
MONGO_URI = 'mongodb://{0}:{1}/'.format(MONGO_HOST, MONGO_PORT)

# Globals
client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=500)
database = client['sauron']

class MongoService():
    """
    Dedicated class for mongo operations. It requires no instance to run.
    """
    @staticmethod
    def insert(collection, data):
        """
        Inserts a given document into a collection;
        :param collection: (str)
        :param data: (dict)
        :returns: (tuple) (doc_id, error)
        """
        try:
            document = database[collection].insert_one(data)
            doc_id = document.inserted_id
            print("Document insertion completed. ID: {}".format(doc_id))
            return doc_id, None
        except Exception as e:
            message = "Error while inserting data into local MongoDB: {}.".\
                format(str(e))
            print(message)
            return (None, message)

    @staticmethod
    def read(collection, query=None):
        """
        Reads data from a collection given a query
        :param collection: (str)
        :param query: (dict) - Optional.
        :returns: (data, error)
        """
        try:
            cursor = database[collection].find(query)
            data = json.loads(json_util.dumps(cursor))
            print("Data read successful.")
            return (data, None)
        except Exception as e:
            message = "Error while reading from local MongoDB: {}.".\
                format(str(e))
            print(message)
            return (None, message)
