import pytest
import json
import lib.MongoAddressClient as db
import lib.secrets.client_secrets as client_secrets
import lib.secrets.admin_secrets as admin_secrets

"""
Unit tests for the backend are implemented here
"""

# Default testing ones for now
username = "Lolo"
password = "1s2s3s4s5s"

entries = [{}]
fields = [{}]


def test_createAddressBook():
    client = db.MongoAddressClient()
    client.add_address_book(username, password)
    assert client.get_address_book(username, password) is not None

def test_getInvalidAddressBook():
    client = db.MongoAddressClient()
    client.add_address_book(username, password)
    assert client.get_address_book(username+"1", password+"1") is None

def test_createEntry():
    client = db.MongoAddressClient()
    client.add_address_book(username, password)
    address_id = client.get_address_book(username, password)
    client.update_address_book_entries(address_book_id=address_id, entries=entries)
    returned_entries = client.get_address_book_entries(address_book_id=address_id)
    assert returned_entries == entries


def test_createField():
    client = db.MongoAddressClient()
    client.add_address_book(username, password)
    address_id = client.get_address_book(username, password)
    client.update_address_book_fields(address_book_id=address_id, fields=fields)
    returned_fields = client.get_address_book_fields(address_book_id=address_id)
    assert returned_fields == fields