"""revocation module"""


import json
from secure_all.exception.access_management_exception import AccessManagementException
from secure_all.data.access_key import AccessKey
from secure_all.storage.keys_json_store import KeysJsonStore
from secure_all.storage.temporal_revocations_json_store import TemporalRevocationsJsonStore
from secure_all.storage.final_revocations_json_store import FinalRevocationsJsonStore
from secure_all.data.attributes.attribute_key import Key
from secure_all.data.attributes.attribute_revocation import Revoc
from secure_all.data.attributes.attribute_reason import Reason

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

            emails = found_key.notification_emails

            if data["Revocation"] == "Final":
                store_final_revocations = FinalRevocationsJsonStore()
                if store_final_revocations.find_item(found_key.key) is None:
                    store.delete_item(found_key.key)
                    store.save_store()

                    store_final_revocations.add_item(found_key)
                    store_final_revocations.save_store()
                else:
                    raise AccessManagementException("La clave fue revocada previamente por este método")

            elif data["Revocation"] == "Temporal":
                store_temporal_revocations = TemporalRevocationsJsonStore()
                if store_temporal_revocations.find_item(found_key.key) is None:
                    store.delete_item(found_key.key)
                    store.save_store()

                    store_temporal_revocations.add_item(found_key)
                    store_temporal_revocations.save_store()
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

        def is_valid(self, file):
            try:
                with open(file, "r", encoding="utf-8", newline="") as json_file:
                    data = json.load(json_file)
            except FileNotFoundError as ex:
                raise AccessManagementException \
                    (
                    "El archivo de entrada tiene algún problema relacionado con su formato o con su acceso.") from ex
            except json.JSONDecodeError as ex:
                raise AccessManagementException("JSON Decode Error - Wrong JSON Format") from ex

            try:
                print(data["Key"])
                key = Key(data["Key"]).value
                revocation = Revoc(data["Revocation"]).value
                reason = Reason(data["Reason"]).value

                return True

            except KeyError as ex:
                raise AccessManagementException("Error al descodificar json") from ex





    __instance = None

    def __new__(cls):
        if not Revocation.__instance:
            Revocation.__instance = Revocation.__Revocation()
        return Revocation.__instance

    def __getattr__(self, name):
        return getattr(self.__instance, name)

    def __setattr__(self, name, valor):
        return setattr(self.__instance, name, valor)
