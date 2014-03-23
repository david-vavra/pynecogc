__author__ = 'David Vavra'

import socket

VLAN_MIN=1
VLAN_MAX=4094

""" Exceptions  """
class InvalidData(Exception):
    def __init__(self,message,*data):
        self.message = message
        self.msg=message
        self.data = data

class ErrRequiredData(InvalidData):
    pass

class ErrOptionalData(InvalidData):
    pass

class InvalidVlanRange(ErrRequiredData):
    pass

class InvalidInterface(ErrOptionalData):
    pass

class InvalidAcl(ErrRequiredData):
    pass

class InvalidMask(ErrRequiredData):
    pass


def validateVlanRange(vlanRangeToValidate):
    """
        Parses given vlan range, supported formats are:
            commas separated list: 1,3,4
            dash separated first and last vlan of the range: 1-4094
    """

    vlanRange = []
    isSingleVlan = True

    try:
        int(vlanRangeToValidate)
    except ValueError:
        isSingleVlan = False

    if isSingleVlan: return vlanRange.append(vlanRangeToValidate)

    for commaSepVlan in vlanRangeToValidate.split(','):

        isSingleVlan = True
        try:
            int(commaSepVlan)
        except ValueError:
            isSingleVlan = False

        if isSingleVlan: vlanRange.append(commaSepVlan)
        else:
            dashSepVlan = commaSepVlan.split('-',1)
            isSingleVlan = True
            try:
                int(dashSepVlan[0])
                int(dashSepVlan[1])
            except ValueError as e:
                return False
    return True

def isValidIP(ip):
    """ return boolean value based on whether given argument ip is a valid IP address """
    try:
        """ first, test if ip is a valid ipv4 addr """
        socket.inet_pton(socket.AF_INET,ip)
        return 4
    except socket.error:
        pass
    try:
        """ test if ip is a valid ipv6 addr """
        socket.inet_pton(socket.AF_INET6,ip)
        return 6
    except socket.error:
        pass
    return False
