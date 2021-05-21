"""module with an auxiliary class"""

import json
from secure_all.data.access_key import AccessKey
from secure_all.storage.keys_json_store import KeysJsonStore
from secure_all.storage.temporal_revocations_json_store import TemporalRevocationsJsonStore
from secure_all.storage.final_revocations_json_store import FinalRevocationsJsonStore

# pylint:disable=invalid-name
# pylint:disable=no-self-use
# pylint:disable=import-outside-toplevel
# pylint:disable=raise-missing-from


class AuxiliarRevocate:
    """ class containing auxiliary funcionts for revocating"""
    class __AuxiliarRevocate:
        """private class for singleton programming"""
        # avoids line too long and solves an error in tests
        _PART1 = "El archivo de entrada tiene algún problema"
        _PART2 = " relacionado con su formato o con su acceso."
        _INCORRECT_FORMAT = _PART1 + _PART2
        _DECODE_ERROR = "JSON Decode Error - Wrong JSON Format"
        _CLAVE_NO_EXISTE = "La clave recibida no existe"
        _CLAVE_CADUCADA = "La clave recibida ha caducado"
        _ALREADY_REVOKED = "La clave fue revocada previamente por este método"

        def __init__(self):
            pass

        def open_revocate(self, file):
            """opens a revocation file"""
            from secure_all import AccessManagementException
            try:
                with open(file, "r", encoding="utf-8", newline="") as json_file:
                    data = json.load(json_file)
            except FileNotFoundError as ex:
                raise AccessManagementException(self._INCORRECT_FORMAT) from ex
            except json.JSONDecodeError as ex:
                raise AccessManagementException(self._DECODE_ERROR) from ex

            return data

        def find_key(self, data):
            """finds the key to revocate"""
            from secure_all import AccessManagementException
            try:
                key = data["Key"]
            except KeyError as ex:
                raise AccessManagementException(self._CLAVE_NO_EXISTE) from ex

            store = KeysJsonStore()
            try:
                found_key = AccessKey.create_key_from_id(key)
                found_key.is_valid()
            except AccessManagementException as ex:
                if ex.message == "key invalid":
                    raise AccessManagementException(self._INCORRECT_FORMAT)
                raise AccessManagementException(self._CLAVE_CADUCADA) from ex

            if found_key is None:
                raise AccessManagementException(self._CLAVE_NO_EXISTE)

            emails = found_key.notification_emails

            self.update_revocation_stores(data, found_key, store)

            return emails

        def update_revocation_stores(self, data, found_key, store):
            """updates the stores after changing them"""
            from secure_all import AccessManagementException
            if data["Revocation"] == "Final":
                store_final_revocations = FinalRevocationsJsonStore()
                if store_final_revocations.find_item(found_key.key) is None:
                    store.delete_item(found_key.key)
                    store.save_store()

                    store_final_revocations.add_item(found_key)
                    store_final_revocations.save_store()
                else:
                    raise AccessManagementException(self._ALREADY_REVOKED)

            elif data["Revocation"] == "Temporal":
                store_temporal_revocations = TemporalRevocationsJsonStore()
                if store_temporal_revocations.find_item(found_key.key) is None:
                    store.delete_item(found_key.key)
                    store.save_store()

                    store_temporal_revocations.add_item(found_key)
                    store_temporal_revocations.save_store()
                else:
                    raise AccessManagementException(self._ALREADY_REVOKED)

            else:
                raise AccessManagementException(self._INCORRECT_FORMAT)

    __instance = None

    def __new__(cls):
        if not AuxiliarRevocate.__instance:
            AuxiliarRevocate.__instance = AuxiliarRevocate.__AuxiliarRevocate()
        return AuxiliarRevocate.__instance

    def __getattr__(self, name):
        return getattr(self.__instance, name)

    def __setattr__(self, name, valor):
        return setattr(self.__instance, name, valor)
