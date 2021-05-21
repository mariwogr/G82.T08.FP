import json
from secure_all.data.access_key import AccessKey
from secure_all.storage.keys_json_store import KeysJsonStore
from secure_all.storage.temporal_revocations_json_store import TemporalRevocationsJsonStore
from secure_all.storage.final_revocations_json_store import FinalRevocationsJsonStore


class AuxiliarRevocate:
    class __AuxiliarRevocate:

        def __init__(self):
            pass

        def open_revocate(self, file):
            from secure_all import AccessManagementException
            try:
                with open(file, "r", encoding="utf-8", newline="") as json_file:
                    data = json.load(json_file)
            except FileNotFoundError as ex:
                raise AccessManagementException \
                    ("El archivo de entrada tiene algún problema relacionado con su formato o con su acceso.") from ex
            except json.JSONDecodeError as ex:
                raise AccessManagementException("JSON Decode Error - Wrong JSON Format") from ex

            return data

        def find_key(self, data):
            from secure_all import AccessManagementException
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
                    raise AccessManagementException(
                        "El archivo de entrada tiene algún problema relacionado con su formato o con su acceso.")
                raise AccessManagementException("La clave recibida ha caducado") from ex

            if found_key is None:
                raise AccessManagementException("La clave recibida no existe")

            emails = found_key.notification_emails

            self.update_revocation_stores(data, found_key, store)

            return emails

        def update_revocation_stores(self, data, found_key, store):
            from secure_all import AccessManagementException
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
                raise AccessManagementException(
                    "El archivo de entrada tiene algún problema relacionado con su formato o con su acceso.")

    __instance = None

    def __new__(cls):
        if not AuxiliarRevocate.__instance:
            AuxiliarRevocate.__instance = AuxiliarRevocate.__AuxiliarRevocate()
        return AuxiliarRevocate.__instance

    def __getattr__(self, name):
        return getattr(self.__instance, name)

    def __setattr__(self, name, valor):
        return setattr(self.__instance, name, valor)
