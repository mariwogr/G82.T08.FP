"""Implements the KeysJSON Store"""
from secure_all.storage.json_store import JsonStore
from secure_all.cfg.access_manager_config import JSON_FILES_PATH
from secure_all.exception.access_management_exception import AccessManagementException


# pylint: disable=duplicate-code

##### Hacemos disable del código duplicado porque final y temporal revocations y keys_json_store
##### tienen el código muy parecido pero al intentar hacer refactor nos dieron batantes problemas
##### y optamos a hacer rollback finalmente

class FinalRevocationsJsonStore:
    """Extends JsonStore """

    class __FinalRevocationsJsonStore(JsonStore):
        # pylint: disable=invalid-name

        ID_FIELD = "_AccessKey__key"

        ACCESS_CODE = "_AccessKey__access_code"
        DNI = "_AccessKey__dni"
        MAIL_LIST = "_AccessKey__notification_emails"
        INVALID_ITEM = "Invalid item to be stored as a key"
        KEY_ALREADY_STORED = "key already found in storeRequest"
        _FILE_PATH = JSON_FILES_PATH + "storeFinalRevocations.json"
        _ID_FIELD = ID_FIELD

        def add_item(self, item):
            """Implementing the restrictions related to avoid duplicated keys"""
            # pylint: disable=import-outside-toplevel,cyclic-import
            from secure_all.data.access_key import AccessKey

            if not isinstance(item, AccessKey):
                raise AccessManagementException(self.INVALID_ITEM)

            if not self.find_item(item.key) is None:
                raise AccessManagementException(self.KEY_ALREADY_STORED)

            return super().add_item(item)

    __instance = None

    def __new__(cls):
        if not FinalRevocationsJsonStore.__instance:
            FinalRevocationsJsonStore.__instance = \
                FinalRevocationsJsonStore.__FinalRevocationsJsonStore()
        return FinalRevocationsJsonStore.__instance

    def __getattr__(self, nombre):
        return getattr(self.__instance, nombre)

    def __setattr__(self, nombre, valor):
        return setattr(self.__instance, nombre, valor)
