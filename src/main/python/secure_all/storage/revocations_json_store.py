"""Implements the KeysJSON Store"""
from secure_all.storage.keys_json_store import KeysJsonStore
from secure_all.cfg.access_manager_config import JSON_FILES_PATH


class RevocationsJsonStore:
    """Extends JsonStore """

    class __RevocationsJsonStore(KeysJsonStore):
        # pylint: disable=invalid-name

        _FILE_PATH = JSON_FILES_PATH + "storeRevocations.json"

    __instance = None

    def __new__(cls):
        if not KeysJsonStore.__instance:
            KeysJsonStore.__instance = KeysJsonStore.__KeysJsonStore()
        return KeysJsonStore.__instance

    def __getattr__(self, nombre):
        return getattr(self.__instance, nombre)

    def __setattr__(self, nombre, valor):
        return setattr(self.__instance, nombre, valor)
