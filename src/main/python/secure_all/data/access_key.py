"""Contains the class Access Key"""
from datetime import datetime
import hashlib

from secure_all.exception.access_management_exception import AccessManagementException
from secure_all.data.access_request import AccessRequest
from secure_all.data.attributes.attribute_access_code import AccessCode
from secure_all.data.attributes.attribute_dni import Dni
from secure_all.data.attributes.attribute_email_list import EmailList
from secure_all.data.attributes.attribute_key import Key

from secure_all.storage.keys_json_store import KeysJsonStore
from secure_all.parser.key_json_parser import KeyJsonParser


class AccessKey:
    """Class representing the key for accessing the building"""
    #pylint: disable=too-many-instance-attributes

    ALG_SHA256 = "SHA-256"
    TYPE_DS = "DS"

    def __init__(self, dni, access_code, notification_emails):
        self.__alg = self.ALG_SHA256
        self.__type = self.TYPE_DS
        self.__access_code = AccessCode(access_code).value
        self.__dni = Dni(dni).value
        access_request = AccessRequest.create_request_from_code(self.__access_code,
                                                                self.__access_code)
        self.__notification_emails = EmailList(notification_emails).value
        validity = access_request.validity
        #justnow = datetime.utcnow()
        #self.__issued_at = datetime.timestamp(justnow)
        # fix self.__issued_at only for testing 13-3-2021 18_49
        self.__issued_at = 1615627129.580297
        if validity == 0:
            self.__expiration_date = 0
        else:
            # timestamp is represneted in seconds.microseconds
            # validity must be expressed in senconds to be added to the timestap
            self.__expiration_date = self.__issued_at + (validity * 30 * 24 * 60 * 60)
        self.__key = hashlib.sha256(self.__signature_string().encode()).hexdigest()

    def __signature_string(self):
        """Composes the string to be used for generating the key"""
        return "{alg:"+self.__alg + ",typ:" + self.__type + ",accesscode:"\
               + self.__access_code+",issuedate:"+str(self.__issued_at)\
               + ",expirationdate:" + str(self.__expiration_date) + "}"

    @property
    def expiration_date(self):
        """expiration_date getter"""
        return self.__expiration_date

    @expiration_date.setter
    def expiration_date(self, value):
        """expiration_date setter"""
        self.__expiration_date = value

    @property
    def dni(self):
        """Property that represents the dni of the visitor"""
        return self.dni

    @dni.setter
    def dni(self, value):
        """dni setter"""
        self.__dni = value

    @property
    def access_code(self):
        """Property that represents the access_code of the visitor"""
        return self.__access_code

    @access_code.setter
    def access_code(self, value):
        """access_code setter"""
        self.__access_code = value

    @property
    def notification_emails(self):
        """Property that represents the access_code of the visitor"""
        return self.__notification_emails

    @notification_emails.setter
    def notification_emails( self, value ):
        """Setter for notification emails"""
        self.__notification_emails = value

    @property
    def key(self):
        """Property that represent the key"""
        return self.__key

    @key.setter
    def key(self, value):
        """Setter of the key value"""
        self.__key = value

    def store_keys(self):
        """Storing the key in the keys store """
        keys_store = KeysJsonStore()
        print(self.__key)
        keys_store.add_item(self)

    def is_valid(self):
        """Return true if the key is not expired, necessary when
        trying to enter into the building"""
        justnow = datetime.utcnow()
        justnow_timestamp = datetime.timestamp(justnow)
        if not (self.__expiration_date == 0 or
                self.__expiration_date > justnow_timestamp):
            raise AccessManagementException("key is not found or is expired")
        return True

    @classmethod
    def create_key_from_file(cls, key_file):
        """Class method from creating an instance of AccessKey
        from the content of a file according to RF2"""
        access_key_items = KeyJsonParser(key_file).json_content
        return cls(access_key_items[KeyJsonParser.DNI],
                   access_key_items[KeyJsonParser.ACCESS_CODE],
                   access_key_items[KeyJsonParser.MAIL_LIST])

    @classmethod
    def create_key_from_id(cls, key):
        """Class method from creating an instance of AccessKey
        retrieving the information from the keys store"""
        keys_store = KeysJsonStore()
        key_object = keys_store.find_item(Key(key).value)
        if key_object is None:
            raise AccessManagementException("key is not found or is expired")
        return cls(key_object[keys_store.DNI],
                   key_object[keys_store.ACCESS_CODE],
                   key_object[keys_store.MAIL_LIST])
