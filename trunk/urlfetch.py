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

from urllib2 import Request, urlopen, URLError

def geturl(url):
    user_agent =  'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'
    headers = { 'User-Agent' : user_agent }
    req = Request(url, None, headers)
    try:
        f = urlopen(req)

        # Try and obtain the Content-Type of the URL
        info = f.info()
        print info
        if 'Content-Type' in info:
            ct = info['Content-Type']
        else:
            ct = None
    except URLError, e:
        if hasattr(e, 'reason'):
            return 201, "Could not fetch %s. Got: %s" % (url, e.reason), None
        elif hasattr(e, 'code'):
            return 201, "Could not fetch %s: %d error" % (url, e.code), None
    return 001, f.read(), ct

def main():
    url = "http://www.is-not-my.name"
    rc, content, type = geturl(url)
    print type

# Call main function.
if (__name__ == "__main__"):
    main()
