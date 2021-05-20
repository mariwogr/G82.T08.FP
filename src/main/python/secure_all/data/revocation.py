"""revocation module"""


import json
from secure_all.exception.access_management_exception import AccessManagementException
from secure_all.data.access_key import AccessKey
from secure_all.storage.keys_json_store import KeysJsonStore
from secure_all.storage.revocations_json_store import RevocationsJsonStore
from secure_all import JSON_FILES_PATH

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
                    ("El archivo de entrada tiene algún problema relacionado con su formato o con su acceso.") from ex
            except json.JSONDecodeError as ex:
                raise AccessManagementException("JSON Decode Error - Wrong JSON Format") from ex

            try:
                key = data["Key"]
            except KeyError as ex:
                raise AccessManagementException("La clave recibida no existe") from ex

            store = KeysJsonStore()
            try:
                found_key = AccessKey.create_key_from_id(key)
                found_key.is_valid()
            except AccessManagementException as ex:
                if ex.message == "key invalid":
                    raise AccessManagementException("El archivo de entrada tiene algún problema relacionado con su formato o con su acceso.")
                raise AccessManagementException("La clave recibida ha caducado") from ex

            if found_key is None:
                raise AccessManagementException("La clave recibida no existe")
            """
            print(found_key.revocation)
            if found_key.revocation:
                raise AccessManagementException("La clave fue revocada previamente por este método")
            found_key.revocation = True
            print(found_key.revocation)
            """

            emails = found_key.notification_emails

            if data["Revocation"] == "Final":
                store.delete_item(found_key.key)
                store.save_store()

            elif data["Revocation"] == "Temporal":
                store_revocations = RevocationsJsonStore()
                if store_revocations.find_item(found_key.key) is None:
                    store.delete_item(found_key.key)
                    store.save_store()

                    store_revocations.add_item(found_key)
                    store_revocations.save_store()
                else:
                    raise AccessManagementException("La clave fue revocada previamente por este método")

            else:
                raise AccessManagementException("El archivo de entrada tiene algún problema relacionado con su formato o con su acceso.")
            """
            store.add_item(found_key)
            store.save_store()
            print(store.__dict__)
            """
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
