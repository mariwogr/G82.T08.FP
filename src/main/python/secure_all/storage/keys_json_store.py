"""Implements the RequestsJSON Store"""
from secure_all.storage.json_store import JsonStore
from secure_all.exception.access_management_exception import AccessManagementException
from secure_all.cfg.access_manager_config import JSON_FILES_PATH


class KeysJsonStore():
    """Extends JsonStore """
    class __KeysJsonStore(JsonStore):
        #pylint: disable=invalid-name
        ID_FIELD = "_AccessKey__key"
        ACCESS_CODE = "_AccessKey__access_code"
        DNI = "_AccessKey__dni"
        MAIL_LIST = "_AccessKey__notification_emails"
        INVALID_ITEM = "Invalid item to be stored as a key"
        KEY_ALREADY_STORED = "key already found in storeRequest"

        _FILE_PATH = JSON_FILES_PATH + "storeKeys.json"
        _ID_FIELD = ID_FIELD

        def add_item( self, item):
            """Implementing the restrictions related to avoid duplicated keys"""
            #pylint: disable=import-outside-toplevel,cyclic-import
            from secure_all.data.access_key import AccessKey

            if not isinstance(item,AccessKey):
                raise AccessManagementException(self.INVALID_ITEM)

            if not self.find_item(item.key) is None:
                raise AccessManagementException(self.KEY_ALREADY_STORED)

            return super().add_item(item)

    __instance = None

    def __new__( cls ):
        if not KeysJsonStore.__instance:
            KeysJsonStore.__instance = KeysJsonStore.__KeysJsonStore()
        return KeysJsonStore.__instance

    def __getattr__ ( self, nombre ):
        return getattr(self.__instance, nombre)

    def __setattr__ ( self, nombre, valor ):
        return setattr(self.__instance, nombre, valor)
