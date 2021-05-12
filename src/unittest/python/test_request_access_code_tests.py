""" doc """

import unittest
import csv
from secure_all import AccessManager, AccessManagementException, \
    AccessRequest, JSON_FILES_PATH, RequestJsonStore



class MyTestCase(unittest.TestCase):
    """ doc """

    # pylint: disable=no-member

    @classmethod
    def setUpClass(cls):
        """ inicializo el entorno de prueba """
        requests_store = RequestJsonStore()
        requests_store.empty_store()


    def test_parametrized_cases_tests( self ):
        """Parametrized cases read from testingCases_RF1.csv"""
        my_cases = JSON_FILES_PATH + "testingCases_RF1.csv"
        with open(my_cases, newline='', encoding='utf-8') as csvfile:
            param_test_cases = csv.DictReader(csvfile, delimiter=';')
            my_code = AccessManager()
            for row in param_test_cases:
                print("Param:" + row[ 'ID TEST' ] + row[ "VALID INVALID" ])
                if row[ "VALID INVALID" ] ==  "VALID":
                    valor = my_code.request_access_code( row[ "DNI" ], row[ "NAME SURNAME" ],
                                                         row[ "ACCESS TYPE" ],  row[ "email" ],
                                                         int(row[ "VALIDITY" ]))
                    self.assertEqual( row[ 'EXPECTED RESULT' ], valor)
                    # Check if this DNI is store in storeRequest.json
                    generated_request = AccessRequest.create_request_from_code(valor,row[ "DNI" ])
                    my_request = AccessRequest(row[ "DNI" ], row[ "NAME SURNAME" ],
                                               row[ "ACCESS TYPE" ],  row[ "email" ],
                                               int(row[ "VALIDITY" ]))
                    self.assertDictEqual(generated_request.__dict__, my_request.__dict__)
                else:
                    with self.assertRaises(AccessManagementException) as c_m:
                        valor = my_code.request_access_code(row[ "DNI" ], row[ "NAME SURNAME" ],
                                                            row[ "ACCESS TYPE" ], row[ "email" ],
                                                            int(row[ "VALIDITY" ]))
                    self.assertEqual(c_m.exception.message, row[ 'EXPECTED RESULT' ])

    def test_invalid_days_character(self):
        """Testing an character instead of a number for days"""
        my_code = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_code.request_access_code("12345678Z", "Pedro Martin",
                                        "Resident", "test@test.com", "a")
        self.assertEqual(c_m.exception.message, "days invalid")

if __name__ == '__main__':
    unittest.main()
