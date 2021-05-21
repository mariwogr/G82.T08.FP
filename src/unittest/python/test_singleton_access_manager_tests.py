"""Testing of Singleton in Access Manager"""

import unittest

from secure_all import AccessManager, KeysJsonStore, RequestJsonStore,\
    AccessLogJsonStore, Revocation
from secure_all.data.attributes.attribute_dni import Dni
from secure_all.storage.temporal_revocations_json_store import TemporalRevocationsJsonStore
from secure_all.storage.final_revocations_json_store import FinalRevocationsJsonStore
from secure_all.data.auxiliary_functions.auxiliar_revocate import AuxiliarRevocate

# pylint:disable=too-many-locals


class MyTestCase(unittest.TestCase):
    """Test case for the singletons"""
    def test_singleton_access_manager( self ):
        """Instance the three singletons and test they're equal
            Instance objects from non singleton class and test they're differet"""
        access_manager_1 = AccessManager()
        access_manager_2 = AccessManager()
        access_manager_3 = AccessManager()

        self.assertEqual(access_manager_1, access_manager_2)
        self.assertEqual(access_manager_2, access_manager_3)
        self.assertEqual(access_manager_3, access_manager_1)

        request_json_store_1 = RequestJsonStore()
        request_json_store_2 = RequestJsonStore()
        request_json_store_3 = RequestJsonStore()

        self.assertEqual(request_json_store_1, request_json_store_2)
        self.assertEqual(request_json_store_2, request_json_store_3)
        self.assertEqual(request_json_store_3, request_json_store_1)

        keys_json_store_1 = KeysJsonStore()
        keys_json_store_2 = KeysJsonStore()
        keys_json_store_3 = KeysJsonStore()

        self.assertEqual(keys_json_store_1, keys_json_store_2)
        self.assertEqual(keys_json_store_2, keys_json_store_3)
        self.assertEqual(keys_json_store_3, keys_json_store_1)

        access_log_json_store_1 = AccessLogJsonStore()
        access_log_json_store_2 = AccessLogJsonStore()
        access_log_json_store_3 = AccessLogJsonStore()

        self.assertEqual(access_log_json_store_1, access_log_json_store_2)
        self.assertEqual(access_log_json_store_2, access_log_json_store_3)
        self.assertEqual(access_log_json_store_3, access_log_json_store_1)

        revocation_1 = Revocation()
        revocation_2 = Revocation()
        revocation_3 = Revocation()

        self.assertEqual(revocation_1, revocation_2)
        self.assertEqual(revocation_2, revocation_3)
        self.assertEqual(revocation_3, revocation_1)

        trjs_1 = TemporalRevocationsJsonStore()
        trjs_2 = TemporalRevocationsJsonStore()
        trjs_3 = TemporalRevocationsJsonStore()

        self.assertEqual(trjs_1, trjs_2)
        self.assertEqual(trjs_2, trjs_3)
        self.assertEqual(trjs_3, trjs_1)

        frjs_1 = FinalRevocationsJsonStore()
        frjs_2 = FinalRevocationsJsonStore()
        frjs_3 = FinalRevocationsJsonStore()

        self.assertEqual(frjs_1, frjs_2)
        self.assertEqual(frjs_2, frjs_3)
        self.assertEqual(frjs_3, frjs_1)

        ar_1 = AuxiliarRevocate()
        ar_2 = AuxiliarRevocate()
        ar_3 = AuxiliarRevocate()

        self.assertEqual(ar_1, ar_2)
        self.assertEqual(ar_2, ar_3)
        self.assertEqual(ar_3, ar_1)

        #probamos ahora que dos clases sin singleton devuelven
        #instancias distintas. Por ejemplo con DNI

        dni_1 = Dni("12345678Z")
        dni_2 = Dni("12345678Z")

        self.assertNotEqual(dni_1, dni_2)

if __name__ == '__main__':
    unittest.main()
