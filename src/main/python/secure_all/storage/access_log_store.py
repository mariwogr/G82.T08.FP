"""Implements the KeysJSON Store"""
from secure_all.storage.json_store import JsonStore
from secure_all.exception.access_management_exception import AccessManagementException
from secure_all.cfg.access_manager_config import JSON_FILES_PATH


class AccessLogJsonStore:
    """Extends JsonStore """
    class __AccessLogJsonStore(JsonStore):
        #pylint: disable=invalid-name
        ID_FIELD = "_OpenDoor__code"
        ACCESS_TIME = "_OpenDoor__access_time"
        INVALID_ITEM = "Invalid item to be stored as a access register"
        ACCESS_REGISTER_ALREADY_STORE = "Access register already found in storeOpenDoor"

        _FILE_PATH = JSON_FILES_PATH + "storeOpenDoor.json"
        _ID_FIELD = ID_FIELD

        def add_item( self, item):
            """Implementing the restrictions related to avoid duplicated keys"""
            #pylint: disable=import-outside-toplevel,cyclic-import
            from secure_all.data.open_door import OpenDoor

            if not isinstance(item, OpenDoor):
                raise AccessManagementException(self.INVALID_ITEM)

            if not self.find_item(item) is None:
                raise AccessManagementException(self.ACCESS_REGISTER_ALREADY_STORE)
            print("item: ", item)
            return super().add_item(item)

    __instance = None

    def __new__(cls):
        if not AccessLogJsonStore.__instance:
            AccessLogJsonStore.__instance = AccessLogJsonStore.__AccessLogJsonStore()
        return AccessLogJsonStore.__instance

    def __getattr__(self, nombre):
        return getattr(self.__instance, nombre)

    def __setattr__(self, nombre, valor):
        return setattr(self.__instance, nombre, valor)
