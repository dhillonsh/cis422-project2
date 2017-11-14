"""
Create the admin user, client user, and the database
"""
import sys
import os
import subprocess
from pymongo import MongoClient

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                '../'))

import secrets.admin_secrets as admin_secrets
import secrets.client_secrets as client_secrets


def create_admin_user():
    """Create the base admin user
    """
    print("Attempting to create admin user")
    add_user_command = \
        "mongo --eval \"db.getSiblingDB('admin').addUser('{0}', '{1}', false);\"".format(admin_secrets.admin_user,
                                                                                         admin_secrets.admin_pw)
    subprocess.call(add_user_command, shell=True)
    print("Created admin user")

def create_client_user():
    """Create the base client user
    """
    MONGO_ADMIN_URL = "mongodb://{}:{}@{}:{}/admin".format(admin_secrets.admin_user,
                                                           admin_secrets.admin_pw,
                                                           admin_secrets.host,
                                                           admin_secrets.port)

    try:
        dbclient = MongoClient(MONGO_ADMIN_URL)
        db = getattr(dbclient, client_secrets.db)
        print("Got database {}".format(client_secrets.db))
        print("Attempting to create user")
        db.add_user(client_secrets.db_user,
                    password=client_secrets.db_user_pw)
        print("Created user {}".format(client_secrets.db_user))
    except Exception as err:
        print("Failed")
        print(err)

if __name__ == "__main__":
    create_admin_user()
    create_client_user()

