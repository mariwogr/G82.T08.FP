"""Attribute class for validating the AccessType"""
from secure_all.exception.access_management_exception import AccessManagementException
from secure_all.data.attributes.attribute import Attribute

MIN_DAYS_GUEST = 2

RESIDENT_DAYS = 0


class AccessType(Attribute):
    """Class that includes the validation rules for access_type
    including the logic for validatin the days"""

    ACCESS_TYPE_GUEST = "Guest"
    ACCESS_TYPE_RESIDENT = "Resident"

    def __init__( self,attr_value ):
        self._validation_pattern =  r'(Resident|Guest)'
        self._error_message = "type of visitor invalid"
        self._attr_value = self._validate(attr_value)

    def validate_days( self, days ):
        """Medhod for validating the """
        if not isinstance(days, int):
            raise AccessManagementException("days invalid")
        if (self._attr_value != self.ACCESS_TYPE_RESIDENT or days != RESIDENT_DAYS) and (
                self._attr_value != self.ACCESS_TYPE_GUEST or days < MIN_DAYS_GUEST or days > 15):
            raise AccessManagementException("days invalid")
        return days
