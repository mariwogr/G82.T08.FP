
import json
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

    @classmethod
    def validate_json_stored(cls, file):
        from secure_all import AccessManagementException
        """ Method to validate the access_log_json_store"""
        try:
            with open(file, 'r', encoding='utf-8', newline="") as checking_file:
                data = json.load(checking_file)
                if isinstance(data, list):
                    for elem in data:
                        #print("elem: ", elem)
                        if Key(elem["_OpenDoor__code"]).value:
                            print("Success reading the code")
                        if type(elem["_OpenDoor__access_time"]) in (float, int):
                            print("success reading the time stamp")
                        else:
                            raise AccessManagementException("Marca de tiempo no válida")  # will raise a ValueError
                    return True

                if Key(data["_OpenDoor__code"]).value:
                    print("Success reading the code")
                if type(data["_OpenDoor__access_time"]) in (float, int):
                    print("success reading the time stamp")
                else:
                    float(data["_OpenDoor__access_time"])  # will raise a ValueError
                return True
        except FileNotFoundError as ex:
            raise AccessManagementException("not found") from ex
        except json.JSONDecodeError as ex:
            raise AccessManagementException("error de decodificación") from ex
        except KeyError as ex:
            raise AccessManagementException("no existe esa clave") from ex

    @property
    def enter_code(self):
        return self.__code

    @property
    def access_time(self):
        return self.__access_time
