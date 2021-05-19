"""revocation module"""


import json
from secure_all.exception.access_management_exception import AccessManagementException
from secure_all.data.access_key import AccessKey
from secure_all.storage.keys_json_store import KeysJsonStore

# pylint:disable=invalid-name
# pylint:disable=no-self-use
# pylint:disable=too-few-public-methods


class Revocation:
    """revocation class"""
    class __Revocation:
        def __init__(self):
            pass

        def revocate(self, file):
            """revocation method"""
            try:
                with open(file, "r", encoding="utf-8", newline="") as json_file:
                    data = json.load(json_file)
            except FileNotFoundError as ex:
                raise AccessManagementException\
                    ("El archivo de entrada tiene algún problema \
                     relacionado con su formato o con su acceso.") from ex
            except json.JSONDecodeError as ex:
                raise AccessManagementException("JSON Decode Error - Wrong JSON Format") from ex

            key = data["Key"]
            try:
                AccessKey.create_key_from_id(key).is_valid()
            except AccessManagementException as ex:
                raise AccessManagementException("La clave recibida ha caducado") from ex

            store = KeysJsonStore().find_item(key)

            if store is None:
                raise AccessManagementException("La clave recibida no existe")

            if store["_AccessKey__revocation"]:
                raise AccessManagementException("La clave fue revocada previamente por este método")
            store["_AccessKey__revocation"] = True

            emails = store["_AccessKey__notification_emails"]
            store.save_store()
            return emails

    __instance = None

    def __new__(cls):
        if not Revocation.__instance:
            Revocation.__instance = Revocation.__Revocation()
        return Revocation.__instance

    def __getattr__(self, name):
        return getattr(self.__instance, name)

    def __setattr__(self, name, valor):
        return setattr(self.__instance, name, valor)