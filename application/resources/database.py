from pymongo import MongoClient

MONGO_URI = 'mongodb://localhost:27017/'

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
            doc_id = document.document_id
            print("Document insertion completed. ID: {}".format(doc_id))
            return doc_id, None
        except Exception as e:
            message = "Error while inserting data into local MongoDB: {}.".\
                format(str(e))
            print(message)
            return (None, message)