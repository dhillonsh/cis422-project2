"""
Control the MongoClient instance for the address_book database.
"""
#pylint: disable=W0312
import lib.secrets.client_secrets as client_secrets
import lib.secrets.admin_secrets as admin_secrets

from pymongo import MongoClient
from bson.objectid import ObjectId

class MongoAddressClient(object):
    """A Mongo Client that serves for altering the `address_book` database.

    Attributes:
        mongo_client_url (str): The path to the running mongo server.
        db_client (obj): The database object that contains a list of collections and their
            documents.
    """


    def __init__(self, database_name):
        self.mongo_client_url = \
            "mongodb://{}:{}@localhost:{}/{}".format(client_secrets.db_user,
                                                     client_secrets.db_user_pw,
                                                     admin_secrets.port,
                                                     database_name)

        mongo_client = MongoClient(self.mongo_client_url)
        self.db_client = getattr(mongo_client, client_secrets.db)


    def is_username_available(self,
                              register_type,
                              username):

        find_query = {
            "username": username
        }

        if register_type == "user":
            return True if self.db_client.registered_users.find_one(find_query) is None else False
        elif register_type == "instructor":
            return True if self.db_client.registered_instructors.find_one(find_query) is None else False
        else:
            return False

    def add_user(self,
                 username,
                 password):

        record = {
            "username": username,
            "password": password,
            "meetings": []
        }
        user_id = str(self.db_client.registered_users.insert(record))
        return user_id

    def add_instructor(self,
                       username,
                       password,
                       is_admin):

        record = {
            "username": username,
            "password": password,
            "meetings": [],
            "is_admin": is_admin
        }
        instructor_id = str(self.db_client.registered_instructors.insert(record))
        return instructor_id


    def add_meeting(self,
                    name,
                    description,
                    instructor_id,
                    participants):

        record = {
            "name": name,
            "description": description,
            "instructor_id": ObjectId(instructor_id),
            "participants": participants
        }
        meeting_id = str(self.db_client.meetings.insert(record))
        self.add_meeting_for_instructor(instructor_id=instructor_id,
                                        meeting_id=meeting_id)

        return meeting_id

    def get_users(self,
                  username_regex):

        find_query = {
            "username": {
                "$regex": username_regex,
                "$options": "i"
            }
        }

        records = []
        for record in self.db_client.registered_users.find(find_query):
            records.append(record["username"])

        return records

    def get_user(self,
                 username,
                 password):

        find_query = {
            "username": username,
            "password": password
        }

        record = self.db_client.registered_users.find_one(find_query)

        if record:
            del record["password"]
            return record

        return None

    def get_user_id(self,
                    username):

        find_query = {
            "username": username
        }

        record = self.db_client.registered_users.find_one(find_query)

        if record:
            return str(record["_id"])

        return None

    def get_user_username(self,
                          user_id):

        find_query = {
            "_id": ObjectId(user_id)
        }

        record = self.db_client.registered_users.find_one(find_query)

        if record:
            return record['username']

        return None


    def get_instructor(self,
                       username,
                       password):

        find_query = {
            "username": username,
            "password": password
        }

        record = self.db_client.registered_instructors.find_one(find_query)

        if record:
            del record["password"]
            return record

        return None

    def get_meeting(self,
                    meeting_id):

        find_query = {
            "_id": ObjectId(meeting_id)
        }

        record = self.db_client.meetings.find_one(find_query)

        return record if record else None


    def get_meetings_list(self,
                          registered_id):
        find_query = {
            "_id": ObjectId(registered_id)
        }

        record = self.db_client.registered_users.find_one(find_query)

        if not record:
            record = self.db_client.registered_instructors.find_one(find_query)

        if not record:
            return None

        return record['meetings']

    def get_all_meetings(self,
                         registered_id):

        meetings_list = self.get_meetings_list(registered_id=registered_id)
        if not meetings_list:
            return None

        meetings = []
        for meeting_id in meetings_list:
            find_query = {
                "_id": ObjectId(meeting_id)
            }
            meeting_entry = self.db_client.meetings.find_one(find_query)

            if not meeting_entry:
                continue

            meetings.append(meeting_entry)

        return meetings

    def get_calendar_data(self,
                          meeting_id):
        find_query = {
            "meeting_id": meeting_id
        }

        records = []
        for record in self.db_client.calendar_data.find(find_query):
            records.append(record)

        return records


    def add_user_to_meeting(self,
                            user_id,
                            meeting_id):
        meetings_list = self.get_meetings_list(registered_id=user_id)

        meetings_list.append(meeting_id)

        where_query = {
            "_id": ObjectId(user_id)
        }

        update_query = {
            "$set": {
                "meetings": meetings_list
            }
        }
        self.db_client.registered_users.update_one(where_query, update_query)



        where_query = {
            "_id": ObjectId(meeting_id)
        }

        participants_list = self.get_meeting(meeting_id=meeting_id)
        if not participants_list:
            return None

        participants_list = participants_list["participants"]
        participants_list.append(user_id)
        update_query = {
            "$set": {
                "participants": participants_list
            }
        }
        self.db_client.meetings.update_one(where_query, update_query)



    def add_meeting_for_instructor(self,
                                   instructor_id,
                                   meeting_id):
        meetings_list = self.get_meetings_list(registered_id=instructor_id)

        meetings_list.append(meeting_id)

        where_query = {
            "_id": ObjectId(instructor_id)
        }

        update_query = {
            "$set": {
                "meetings": meetings_list
            }
        }
        self.db_client.registered_instructors.update_one(where_query, update_query)


    def update_calendar_times(self,
                              meeting_id,
                              registered_id,
                              free_times):

        where_query = {
            "meeting_id": meeting_id,
            "registered_id": registered_id
        }

        update_query = {
            "$set": {
                "meeting_id": meeting_id,
                "registered_id": registered_id,
                "free_times": free_times
            }
        }

        self.db_client.calendar_data.update_one(where_query, update_query, upsert=True)


    def update_meeting(self,
                       meeting_id,
                       name,
                       description,
                       participants):

        where_query = {
            "_id": ObjectId(meeting_id)
        }

        update_query = {
            "$set": {
                "name": name,
                "description": description
            }
        }

        if participants is not None:
            update_query["$set"]["participants"] = participants

        self.db_client.meetings.update_one(where_query, update_query)



    def remove_meeting_for_user(self,
                                user_id,
                                meeting_id):
        find_query = {
            "_id": ObjectId(user_id)
        }

        meeting_list = self.get_meetings_list(registered_id=user_id)
        if not meeting_list:
            return None

        meeting_list.remove(meeting_id)

        where_query = {
            "_id": ObjectId(user_id)
        }

        update_query = {
            "$set": {
                "meetings": meeting_list
            }
        }

        self.db_client.registered_users.update_one(where_query, update_query)

        where_query = {
            "_id": ObjectId(meeting_id)
        }

        participants_list = self.get_meeting(meeting_id=meeting_id)
        if not participants_list:
            return None

        participants_list = participants_list["participants"]
        participants_list.remove(user_id)
        update_query = {
            "$set": {
                "participants": participants_list
            }
        }
        self.db_client.meetings.update_one(where_query, update_query)



    def remove_meeting_for_instructor(self,
                                      instructor_id,
                                      meeting_id):
        find_query = {
            "_id": ObjectId(instructor_id)
        }

        record = self.db_client.registered_instructors.find_one(find_query)
        record["meetings"].remove(meeting_id)

        where_query = {
            "_id": ObjectId(instructor_id)
        }

        update_query = {
            "$set": {
                "meetings": record["meetings"]
            }
        }

        self.db_client.registered_instructors.update_one(where_query, update_query)

    def remove_meeting(self,
                       meeting_id):

        participants = self.get_meeting(meeting_id)
        if not participants:
            return

        instructor_id = participants["instructor_id"]
        participants = participants["participants"]

        # Get a list of the participants in the meeting, and remove the meeting from their list
        for participant in participants:
            self.remove_meeting_for_user(user_id=participant,
                                         meeting_id=meeting_id)

        self.remove_meeting_for_instructor(instructor_id=instructor_id,
                                           meeting_id=meeting_id)

        self.db_client.meetings.remove({"_id": ObjectId(meeting_id)})