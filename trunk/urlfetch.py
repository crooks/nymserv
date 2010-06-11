#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 autoindent
#
# Copyright (C) 2009 Steve Crook <steve@mixmin.net>
# $Id$
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTIBILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.

import urllib2

def geturl(url):
    req = urllib2.Request(url)
    try:
        f = urllib2.urlopen(req)
    except urllib2.URLError:
        return 301, "Unable to retreive " + url
    return 001, f.read()
