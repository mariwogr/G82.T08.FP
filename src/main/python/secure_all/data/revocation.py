"""revocation module"""


import json
from secure_all.exception.access_management_exception import AccessManagementException
from secure_all.data.attributes.attribute_key import Key
from secure_all.data.attributes.attribute_revocation import Revoc
from secure_all.data.attributes.attribute_reason import Reason
from secure_all.data.auxiliary_functions.auxiliar_revocate import AuxiliarRevocate

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

            data = AuxiliarRevocate().open_revocate(file)

            return AuxiliarRevocate().find_key(data)


        def is_valid(self, file):

            data = AuxiliarRevocate().open_revocate(file)

            try:
                if "Key" in data.keys() and "Revocation" in data.keys() and "Reason" in data.keys():
                    Key(data["Key"]).value
                    Revoc(data["Revocation"]).value
                    Reason(data["Reason"]).value

                    return True
                else:
                    raise AccessManagementException("Error al descodificar json")

            except KeyError as ex:
                raise AccessManagementException("Error al descodificar json") from ex

        def validate_json_stored(self, file, key):
            """ Method to validate the access_log_json_store"""
            try:
                with open(file, 'r', encoding='utf-8', newline="") as checking_file:
                    data = json.load(checking_file)
                    for elem in data:
                        if elem["_AccessKey__key"] == key:
                            return True  # clave revocada con éxito
                    raise AccessManagementException("La clave fue revocada previamente por este método")
            except FileNotFoundError as ex:
                raise AccessManagementException("not found") from ex
            except json.JSONDecodeError as ex:
                raise AccessManagementException("error de decodificación") from ex
            except KeyError as ex:
                raise AccessManagementException("no existe esa clave") from ex





    __instance = None

    def __new__(cls):
        if not Revocation.__instance:
            Revocation.__instance = Revocation.__Revocation()
        return Revocation.__instance

    def __getattr__(self, name):
        return getattr(self.__instance, name)

    def __setattr__(self, name, valor):
        return setattr(self.__instance, name, valor)
