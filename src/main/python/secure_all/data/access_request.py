"""MODULE: access_request. Contains the access request class"""
import json
import hashlib
from secure_all.exception.access_management_exception import AccessManagementException
from secure_all.data.attributes.attribute_full_name import FullName
from secure_all.data.attributes.attribute_dni import Dni
from secure_all.data.attributes.attribute_access_type import  AccessType
from secure_all.data.attributes.attribute_email import Email
from secure_all.storage.requests_json_store import RequestJsonStore


class AccessRequest:
    """Class representing the access request"""
    #pylint: disable=too-many-arguments

    def __init__( self, id_document, full_name, access_type, email_address, validity ):
        self.__id_document = Dni(id_document).value
        self.__name = FullName(full_name).value
        access_type_object = AccessType(access_type)
        self.__visitor_type = access_type_object.value
        self.__email_address = Email(email_address).value
        self.__validity = access_type_object.validate_days(validity)
        access_type_object = None
        #justnow = datetime.utcnow()
        #self.__time_stamp = datetime.timestamp(justnow)
        #only for testing , fix de time stamp to this value 1614962381.90867 , 5/3/2020 18_40
        self.__time_stamp = 1614962381.90867

    def __str__(self):
        """It returns the json corresponding to the AccessRequest"""
        return "AccessRequest:" + json.dumps(self.__dict__)

    def store_request( self ):
        """It Saves the request in the store"""
        request_store = RequestJsonStore()
        request_store.add_item(self)
        del request_store

    @property
    def validity( self ):
        """Property representing the validity days"""
        return self.__validity

    @property
    def name( self ):
        """Property representing the name and the surname of
        the person who request access to the building"""
        return self.__name
    @name.setter
    def name(self, value):
        """name setter"""
        self.__name = value

    @property
    def visitor_type(self):
        """Property representing the type of visitor: Resident or Guest"""
        return self.__visitor_type
    @visitor_type.setter
    def visitor_type(self, value):
        self.__visitor_type = value

    @property
    def email_address(self):
        """Property representing the requester's email address"""
        return self.__email_address
    @email_address.setter
    def email_address(self, value):
        self.__email_address = value

    @property
    def id_document( self ):
        """Property representing the requester's DNI"""
        return self.__id_document
    @id_document.setter
    def id_document( self, value ):
        self.__id_document = value

    @property
    def time_stamp(self):
        """Read-only property that returns the timestamp of the request"""
        return self.__time_stamp

    @property
    def access_code (self):
        """Property for obtaining the access code according the requirements"""
        return hashlib.md5(self.__str__().encode()).hexdigest()

    @classmethod
    def create_request_from_code( cls, access_code, dni ):
        """Load from the store an AccessRequest from the access_code
        and the dni"""
        request_store = RequestJsonStore()
        request_stored = request_store.find_item(dni)
        if request_stored is None:
            raise AccessManagementException(request_store.NOT_FOUND_IN_THE_STORE)

        request_stored_object = cls(request_stored[ request_store.ID_FIELD ],
                                        request_stored[ request_store.REQUEST__NAME ],
                                        request_stored[ request_store.REQUEST__VISITOR_TYPE ],
                                        request_stored[ request_store.REQUEST__EMAIL_ADDRESS ],
                                        request_stored[ request_store.ACCESS_REQUEST__VALIDITY ])

        if not request_stored_object.access_code == access_code:
            raise AccessManagementException(request_store.NOT_CORRECT_FOR_THIS_DNI)
        return request_stored_object
