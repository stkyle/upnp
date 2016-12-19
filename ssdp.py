# -*- coding: utf-8 -*-
#!/usr/bin/python
"""
"""

import sys
import re
import socket
import time
import struct
import logging

log = logging.getLogger(__name__)

class Header(object)
    HOST = 'HOST'
    CACHE_CONTROL = 'CACHE-CONTROL'
    LOCATION = 'LOCATION'
    NOTIFY_TYPE = 'NT'
    USER_AGENT = 'USER-AGENT'
    """
    ST: Required. Field value contains Search Target. shall be one of the 
    following. (See NT header field in NOTIFY with ssdp:alive above.) 
    Single URI.
    """
    SEARCH_TARGET = 'ST'
    
    """
    MAN: Required by HTTP Extension Framework. Unlike the NTS and ST 
    field values, the field value of the MAN header field is enclosed in 
    double quotes; it defines the scope (namespace) of the extension. shall 
    be "ssdp:discover".
    """
    MAN = 'MAN'
    
    """
    MX: Required. Field value contains maximum wait time in seconds. shall be 
    greater than or equal to 1 and shouldbe less than 5 inclusive. Device 
    responses should be delayed a random duration between 0 and this many
    seconds to balance load for the control point when it processes responses. 
    This value is allowed to be increased if a large number of devices are 
    expected to respond. The MX field value should NOT be increased to 
    accommodate network characteristics such as latency or propagation 
    delay (for more details, see the explanation below). Specified by UPnP 
    vendor. Integer.
    """
    MX = 'MX'
    
    def __init__(self, key, val):
        self.key = key
        self.val = val
    
    def __repr__(self):
        return '%s: %s' % (self.key, self.val)
    
class SSDPMessage(object):
    """Wrapper for Simple Service Discovery Protocol Message.
    
    SSDP uses part of the header field format of HTTP 1.1 as defined in 
    RFC 2616. However, it is NOT based on full HTTP 1.1 as it uses UDP 
    instead of TCP, and it has its own processing rules. This subclause 
    defines the generic format of a SSDP message.
    
    All SSDP messages shall be formatted according to RFC 2616 clause 4.1 
    “generic message”. SSDP messages shall have a start-line and a list of 
    message header fields. SSDP messages should not have a message body. If 
    a SSDP message is received with a message body, the message body is 
    allowed to be ignored.
    """
    
    """
    The message header fields in a SSDP message shall be formatted according 
    to RFC 2616 clause 4.2. This specifies that each message header field 
    consist of a case-insensitive field name followed by a colon (":"), 
    followed by the case-sensitive field value. SSDP restricts allowed field 
    values.
    """
    def __init__(self,**kwargs):
        self.start_line = ''
        self._headers = {}
        self._host = ''


    def add_header(self, key, value):
        self._headers[key.upper()] = value

    def set_man(self, value):
        self._headers[SSDPHeader.MAN] = '"{}"'.format(value)
        
    def set_st(self, value):
        self._headers[SSDPHeader.SEARCH_TARGET] = '{}'.format(value)
                 
            
class SSDPMSearchMessage(SSDPMessage):
    """ """
    start_line = 'M-SEARCH * HTTP/1.1'
    body = '\r\n'
    
    def __init__(self, multicast_addr='239.255.255.250', multicast_port=1900, man='ssdp:discover'):
        self._headers = {}
        self._host = '{0}: {1}'.format(multicast_addr, multicast_port)
        self.add_header(SSDPHeader.HOST, self._host)
        self.set_man('ssdb:discover')
        self.set_st('roku:ecp')
    
    def as_text(self):
        headers = ['{0}: {1}'.format(k,v) for k,v in self._headers.items()]
        msg = '\r\n'.join([self.start_line] + headers + [self.body])
        return msg
   
