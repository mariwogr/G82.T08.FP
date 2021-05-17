from secure_all.data.attributes.attribute_key import Key
from secure_all.storage.access_log_store import AccessLogJsonStore


class OpenDoor:
    def __init__(self, key_sha_256):
        self.__code = Key(key_sha_256).value
        # fix self.__access_time only for testing 13-3-2021 18_49
        self.__access_time = 1615627129.580297

    def store_access(self):
        """Storing the access timestamp in the access log store """
        access_log_store = AccessLogJsonStore()
        access_log_store.add_item(self)

    @property
    def enter_code(self):
        return self.__code

    @property
    def access_time(self):
        return self.__access_time
