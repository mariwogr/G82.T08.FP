"""Implements the RequestsJSON Store"""
from secure_all.storage.json_store import JsonStore
from secure_all.exception.access_management_exception import AccessManagementException
from secure_all.cfg.access_manager_config import JSON_FILES_PATH



class RequestJsonStore():
    """Extends JsonStore"""

    class __RequestJsonStore(JsonStore):
        # pylint: disable=invalid-name
        NOT_CORRECT_FOR_THIS_DNI = "access code is not correct for this DNI"
        INVALID_ITEM = "Invalid item to be stored as a request"
        ID_DOCUMENT_ALREADY_STORED = "id_document found in storeRequest"
        NOT_FOUND_IN_THE_STORE = "DNI is not found in the store"
        ACCESS_REQUEST__VALIDITY = '_AccessRequest__validity'
        REQUEST__EMAIL_ADDRESS = '_AccessRequest__email_address'
        REQUEST__VISITOR_TYPE = '_AccessRequest__visitor_type'
        REQUEST__NAME = '_AccessRequest__name'
        ID_FIELD = '_AccessRequest__id_document'

        _FILE_PATH = JSON_FILES_PATH + "storeRequest.json"
        _ID_FIELD = ID_FIELD

        def add_item( self, item):
            """Implementing the restrictions related to avoid duplicated DNIs in the list
            import of AccessRequest must be placed here instead of at the top of the file
            to avoid circular references"""
            #pylint: disable=import-outside-toplevel,cyclic-import
            from secure_all.data.access_request import AccessRequest

            if not isinstance(item,AccessRequest):
                raise AccessManagementException(self.INVALID_ITEM)

            if not self.find_item(item.id_document) is None:
                raise AccessManagementException(self.ID_DOCUMENT_ALREADY_STORED)

            return super().add_item(item)


    __instance = None

    def __new__( cls ):
        if not RequestJsonStore.__instance:
            RequestJsonStore.__instance = RequestJsonStore.__RequestJsonStore()
        return RequestJsonStore.__instance

    def __getattr__ ( self, nombre ):
        return getattr(self.__instance, nombre)

    def __setattr__ ( self, nombre, valor ):
        return setattr(self.__instance, nombre, valor)
