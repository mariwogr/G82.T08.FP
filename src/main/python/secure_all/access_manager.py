"""Module AccessManager with AccessManager Class """

import json
from secure_all.data.access_key import AccessKey
from secure_all.data.access_request import AccessRequest
from secure_all.data.open_door import OpenDoor
from secure_all import AccessManagementException, KeysJsonStore


class AccessManager:
    """AccessManager class, manages the access to a building implementing singleton """
    #pylint: disable=too-many-arguments,no-self-use,invalid-name, too-few-public-methods
    #pylint: disable=inconsistent-return-statements
    class __AccessManager:
        """Class for providing the methods for managing the access to a building"""

        def request_access_code(self, id_card, name_surname, access_type, email_address, days):
            """ this method give access to the building"""
            my_request = AccessRequest(id_card, name_surname, access_type, email_address, days)
            my_request.store_request()
            return my_request.access_code

        def get_access_key(self, keyfile):
            """Returns the access key for the access code & dni received in a json file"""
            my_key = AccessKey.create_key_from_file(keyfile)
            my_key.store_keys()
            return my_key.key

        def open_door(self, key):
            """Opens the door if the key is valid an it is not expired"""
            if AccessKey.create_key_from_id(key).is_valid():
                OpenDoor(key).store_access()
                return True

        def revoke_key(self, file):
            """Revokes the key"""
            try:
                with open(file, "r", encoding="utf-8", newline="") as json_file:
                    data = json.load(json_file)
            except FileNotFoundError as ex:
                raise AccessManagementException\
                    ("El archivo de entrada tiene algún problema \
                     relacionado con su formato o con su acceso.") \
                    from ex
            except json.JSONDecodeError as ex:
                raise AccessManagementException("JSON Decode Error - Wrong JSON Format") from ex

            key = data["Key"]
            revocation = data["Revocation"]

            try:
                AccessKey.create_key_from_id(key).is_valid()
            except AccessManagementException as ex:
                raise AccessManagementException(" La clave recibida ha caducado.") from ex

            store = KeysJsonStore().find_item(key)

            if store is None:
                raise AccessManagementException("La clave recibida no existe")

            emails = store["_AccessKey__notification_emails"]

            if store["_AccessKey__revocation"]:
                raise AccessManagementException("La clave fue revocada previamente por este método")






    __instance = None

    def __new__(cls):
        if not AccessManager.__instance:
            AccessManager.__instance = AccessManager.__AccessManager()
        return AccessManager.__instance
