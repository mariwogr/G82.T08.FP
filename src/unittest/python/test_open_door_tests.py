"""open_door test cases"""
import unittest
import csv
import json

from secure_all import AccessManager, AccessManagementException, \
    AccessKey, JSON_FILES_PATH, KeysJsonStore, RequestJsonStore, AccessLogJsonStore
from secure_all.data.open_door import OpenDoor


class TestOpenDoor(unittest.TestCase):
    """test class for open_door"""

    # pylint: disable=no-member
    # pylint: disable=no-self-use

    @classmethod
    def setUpClass(cls) -> None:
        # first af all, i introduce all value tha I need for the structural testing
        # remove the old storeKeys
        requests_store = RequestJsonStore()
        keys_store = KeysJsonStore()
        access_log_store = AccessLogJsonStore()
        requests_store.empty_store()
        keys_store.empty_store()
        access_log_store.empty_store()
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
        my_key_expirated.expiration_date = 0
        my_key_expirated.store_keys()

    def test_parametrized_cases_tests(self):
        """Parametrized cases read from testingCases_RF3.csv"""
        my_cases = JSON_FILES_PATH + "testingCases_RF3.csv"
        with open(my_cases, newline='', encoding='utf-8') as csvfile:
            # pylint: disable=no-member
            param_test_cases = csv.DictReader(csvfile, delimiter=';')
            for row in param_test_cases:
                file_name = JSON_FILES_PATH + row["FILE"]
                print("Param:" + row['ID TEST'] + row["VALID INVALID"])
                if row["VALID INVALID"] == "VALID":
                    es_valido = OpenDoor.validate_json_stored(file_name)
                    self.assertEqual(True, es_valido)
                else:
                    with self.assertRaises(AccessManagementException) as c_m:
                        OpenDoor.validate_json_stored(file_name)
                    self.assertEqual(c_m.exception.message, row["EXPECTED RESULT"])

    def test_open_door_bad_key_regex(self):
        """
        #path: regex is not valid , key length is 63 chars
    """
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.open_door \
                ("cc161c01a4bcca82e841b3446e2a3edb3539d72a3a7ec40a07d236998482906")
        self.assertEqual("key invalid", c_m.exception.message)

    def test_open_door_good(self):
        """
    # path: regex ok , key is found , key is not expired, guest
    """
        my_key = AccessManager()
        result = my_key.open_door \
            ("45c3583c3ef003409dfb2d128853e19979b8d70a1dd9ca25d3e974524a1e4658")
        self.assertEqual(True, result)
        self.assertEqual(True, OpenDoor.validate_json_stored(JSON_FILES_PATH + "storeOpenDoor.json"))

    def test_open_door_resident(self):
        """
    # path: regex ok, key is found, expiration date is 0, resident
    """
        my_key = AccessManager()
        result = my_key.open_door \
            ("b51e91628f8a8c5b17e35b813782799511b8af743a09ef6f12c573345455f79e")
        self.assertEqual(True, result)
        self.assertEqual(True, OpenDoor.validate_json_stored(JSON_FILES_PATH + "storeOpenDoor.json"))

    def test_open_door_bad_key_is_not_found(self):
        """
    # path: regex ok, key is not found
    """
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.open_door \
                ("fff00d78646ed41a91d60ec2fc1ed326238e510134ca52e5d9b1de5cbdf2b8ab")

        self.assertEqual("key is not found or is expired", c_m.exception.message)

    def test_open_door_bad_key_is_expired(self):
        """
    # Expired key generated in the SetUpClass method
    """
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.open_door \
                ("459063166d5a8e38ac493d4f523e31cca39bdc2c523d12dc08cae4a983224495")

        self.assertEqual("key is not found or is expired", c_m.exception.message)




if __name__ == '__main__':
    unittest.main()
