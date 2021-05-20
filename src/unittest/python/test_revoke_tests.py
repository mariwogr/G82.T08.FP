"""open_door test cases"""
import unittest
import csv
import json

from secure_all import AccessManager, AccessManagementException, \
    AccessKey, JSON_FILES_PATH, KeysJsonStore, RequestJsonStore


class TestRevocation(unittest.TestCase):
    """test class for open_door"""

    # pylint: disable=no-member
    # pylint: disable=no-self-use
    # pylint: disable=unused-variable

    # unused variable nos lo da por los tests parametrizados, pero no podemos hacer nada con ello

    @classmethod
    def setUpClass(cls) -> None:
        # first af all, i introduce all value tha I need for the structural testing
        # remove the old storeKeys
        requests_store = RequestJsonStore()
        keys_store = KeysJsonStore()
        requests_store.empty_store()
        keys_store.empty_store()
        # introduce a key valid and not expired and guest
        my_manager = AccessManager()
        my_manager.request_access_code("05270358T", "Pedro Martin",
                                       "Resident", "uc3m@gmail.com", 0)

        my_manager.request_access_code("53935158C", "Marta Lopez",
                                       "Guest", "uc3m@gmail.com", 5)

        my_manager.get_access_key(JSON_FILES_PATH + "key_ok.json")

        # introduce a key valid and expiration date = 0 , resident
        my_manager.get_access_key(JSON_FILES_PATH + "key_ok3_resident.json")

        # introduce a key expirated, I need to change expiration date before to store the key
        my_manager.request_access_code("68026939T", "Juan Perez",
                                       "Guest", "expired@gmail.com", 2)
        # expected result 383a8eb306459919ef0dc819405f16a6
        # We generate the AccessKey for this AccessRequest
        my_key_expirated = AccessKey.create_key_from_file(JSON_FILES_PATH +
                                                          "key_ok_testing_expired.json")
        # We manipulate the expiration date to obtain an expired AccessKey
        # my_key_expirated.expiration_date = 0
        # my_key_expirated.store_keys()

    def test_parametrized_cases_tests(self):
        return
        """Parametrized cases read from testingCases_RF4.csv"""
        my_cases = JSON_FILES_PATH + "testingCases_RF4.csv"
        with open(my_cases, newline='', encoding='utf-8') as csvfile:
            # pylint: disable=no-member
            param_test_cases = csv.DictReader(csvfile, delimiter=';')
            for row in param_test_cases:
                file_name = JSON_FILES_PATH + row["FILE"]
                print("Param:" + row['ID TEST'] + row["VALID INVALID"])
                if row["VALID INVALID"] == "VALID":
                    # ENSEÑAR A SERGIO
                    if row["FIELD"] == "Revoking":
                        emails = my_manager.revoke_key(file_name)
                        self.assertEqual(row["EXPECTED RESULT"], emails)
                    else:
                        pass


                else:
                    with self.assertRaises(AccessManagementException) as c_m:
                        my_manager.revoke_key(file_name)
                    self.assertEqual(c_m.exception.message, row["EXPECTED RESULT"])

    def test_revoke_bad_key_regex(self):
        """
        #path: regex is not valid , key length is 63 chars
    """
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "key_small_revoke.json")
        self.assertEqual("El archivo de entrada tiene algún problema relacionado con su formato o con su acceso.",
                         c_m.exception.message)

    def test_revoke_good(self):
        """
    # path: regex ok , key is found , key is not expired, guest
    """
        my_key = AccessManager()
        result = my_key.revoke_key(JSON_FILES_PATH + "key_active_revoke.json")
        self.assertEqual(["mail1@uc3m.es", "mail2@uc3m.es"], result)
        self.assertEqual(True, self.validate_json_stored(JSON_FILES_PATH + "storeKeys.json",
                        "130ad1cc55f0c3dcd25719fb009b535d43b4fe3a3ffe196be97eda5e37f20ded"))

    def test_revoke_resident(self):
        """
    # path: regex ok, key is found, expiration date is 0, resident
    """
        my_key = AccessManager()
        result = my_key.revoke_key(JSON_FILES_PATH + "key_resident_revoke.json")
        self.assertEqual(["mail1@uc3m.es", "mail2@uc3m.es"], result)
        self.assertEqual(True, self.validate_json_stored(JSON_FILES_PATH + "storeKeys.json",
                        "231795d640824b37db595b903ac7f68a77921f8673cbc31efe89e9062c0c864e"))

    def test_revoke_key_expired(self):
        """
    # path: regex ok, key is not found
    """
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "key_expired_revoke.json")
        self.assertEqual("La clave recibida ha caducado", c_m.exception.message)

    def test_revoke_bad_key_is_not_found(self):
        """
    # path: regex ok, key is not found
    """
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "bad_key_revoke.json")
        self.assertEqual("La clave recibida no existe", c_m.exception.message)

    def test_revoke_already_revoked(self):
        """
    # Expired key generated in the SetUpClass method
    """
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "key_already_revoke.json")
        self.assertEqual("La clave fue revocada previamente por este método", c_m.exception.message)

    def validate_json_stored(self, file, key):
        """ Method to validate the access_log_json_store"""
        try:
            with open(file, 'r', encoding='utf-8', newline="") as checking_file:
                data = json.load(checking_file)
                for elem in data:
                    if elem["_AccessKey__key"] == key:
                        if elem["_AccessKey__revocation"]:
                            print("Success revoking")
                            return True         # clave revocada con éxito
                        raise AccessManagementException("La clave fue revocada previamente por este método")
                raise AccessManagementException("La clave fue revocada previamente por este método")
        except FileNotFoundError as ex:
            raise AccessManagementException("not found") from ex
        except json.JSONDecodeError as ex:
            raise AccessManagementException("error de decodificación") from ex
        except KeyError as ex:
            raise AccessManagementException("no existe esa clave") from ex


if __name__ == '__main__':
    unittest.main()
