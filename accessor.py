import os
import datetime
import pymongo
from pymongo import MongoClient

def insertPacket(): 
	MONGOHQ_URL = os.environ.get('127.0.0.1:27017')
	client = MongoClient(MONGOHQ_URL)
	db = client.local
	print db.collection_names()
	collection = db.startup_log
	count = collection.count()
	print "The number of documents you have in this collection is:", count
	monster = {"name": "Dracula",
           	"occupation": "Blood Sucker",
           	"tags": ["vampire", "teeth", "bat"],
           	"date": datetime.datetime.utcnow()
           	}
 
	# Insert the monster document into the monsters collection
	#monster_id = collection.insert(monster)
	print collection.find_one()
	# Print all documents
	#for log in collection.find():
	#    print log
	# Query for a particular monster
	#print collection.find_one({"name": "Dracula"})

def insertStream():
        MONGOHQ_URL = os.environ.get('127.0.0.1:27017')
        client = MongoClient(MONGOHQ_URL)
        db = client.local
        print db.collection_names()
        collection = db.startup_log
        count = collection.count()
        print "The number of documents you have in this collection is:", count
        monster = {"name": "Dracula",
                "occupation": "Blood Sucker",
                "tags": ["vampire", "teeth", "bat"],
                "date": datetime.datetime.utcnow()
                }
	monster_id = collection.insert(monster)

