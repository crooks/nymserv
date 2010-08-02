#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 noautoindent
#
# utils.py - String utilities
#
# Copyright (C) 2010 Steve Crook <steve@mixmin.net>
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

import datetime
import random


def datetimestr():
    """Return a date in the format yyyymmdd.  This is useful for generating
    a component of Message-ID."""
    utctime = datetime.datetime.utcnow()
    utcstamp = utctime.strftime("%Y%m%d%H%M%S")
    return utcstamp

def datestr():
    """As per middate but only return the date element of UTC.  This is used
    for generating log and history files."""
    utctime = datetime.datetime.utcnow()
    utcstamp = utctime.strftime("%Y%m%d")
    return utcstamp

def randstr(numchars):
    """Return a string of random chars"""
    randstring = ""
    while len(randstring) < numchars:
        randstring += random.choice('abcdefghijklmnopqrstuvwxyz')
    return randstring

def messageid(rightpart):
    """Compile a valid Message-ID."""
    leftpart = datetimestr() + "." + randstr(12)
    mid = '<' + leftpart + '@' + rightpart + '>'
    return mid

def underline(char, string):
    "Return a string of char repeated len(string) times."
    string = string.rstrip('\n')
    count = len(string)
    retstr = char * count + '\n\n'
    return retstr

def main():
    mid = messageid('testing.invalid')
    print mid
    print underline('-', mid)
    print "Date: " + datestr()


# Call main function.
if (__name__ == "__main__"):
    main()
