#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    Copyright (C) 2014  David Vavra  (vavra.david@email.cz)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

"""

import socket

VLAN_MIN=1
VLAN_MAX=4094

""" Exceptions  """
class InvalidData(Exception):
    def __init__(self,message,*data):
        self.message = message
        self.msg=message
        self.data = data

""" Thrown when crucial data (with respect to the given feature)
are invalid or missing. """
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
            combination of the two: 1-4,7-11,15,18 ...
    """

    vlanRange = []
    isSingleVlan = True

    try:
        int(vlanRangeToValidate)
    except ValueError:
        isSingleVlan = False

    if isSingleVlan:
        return True

    for commaSepVlan in vlanRangeToValidate.split(','):

        isSingleVlan = True
        try:
            if int(commaSepVlan) > VLAN_MAX or int(commaSepVlan) < VLAN_MIN:
                return False
        except ValueError:
            isSingleVlan = False

        if isSingleVlan: vlanRange.append(commaSepVlan)
        else:
            dashSepVlan = commaSepVlan.split('-',1)
            isSingleVlan = True
            try:
                if int(dashSepVlan[0]) > VLAN_MAX or int(dashSepVlan) < VLAN_MIN:
                    return False
                if int(dashSepVlan[1]) > VLAN_MAX or int(dashSepVlan) < VLAN_MIN:
                    return False
            except ValueError:
                return False
    return True

def isValidIP(ip):
    """ return boolean value based on whether given argument ip is a valid IP address """
    try:
        """ test if ip is a valid ipv4 addr """
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
