# -*- coding: utf-8 -*-
# vim:fileencoding=utf-8

from Zorp.Core import config
from Zorp.Rule import Rule
from Zorp.Service import Service
from Zorp.Zorp import  Z_STACK_PROGRAM
from Zorp.Http import  HttpProxy, HTTP_STK_DATA

from zones import *


class HttpProxyStackingClamAV(HttpProxy):
    def config(self):
        HttpProxy.config(self)
        self.response_stack["GET"] = (HTTP_STK_DATA, (Z_STACK_PROGRAM, "/etc/zorp/clamav_stack.py"))

def default() :
    Service(
        name='HttpServiceStackingClamAV',
        proxy_class=HttpProxyStackingClamAV,
    )

    Rule(
        proto=6,
        src_zone=('client', ),
        dst_zone=('server', ),
        dst_port=(80, ),
        service='HttpServiceStackingClamAV'
    )
