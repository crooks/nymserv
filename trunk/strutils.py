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
import os.path


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

def hours_ago(hrs):
    "Create a timestamp for x hours ago."
    thentime = datetime.datetime.utcnow() - datetime.timedelta(hours=hrs)
    timestamp = thentime.strftime("%Y-%m-%d %H:%M:%S")
    return timestamp

def randstr(numchars):
    """Return a string of random chars"""
    randstring = ""
    while len(randstring) < numchars:
        randstring += random.choice('abcdefghijklmnopqrstuvwxyz')
    return randstring

def pool_filename():
    """File naming format for pool files."""
    return datetimestr() + '.' + randstr(6)

def messageid(rightpart):
    """Compile a valid Message-ID."""
    leftpart = randstr(10) + "." + randstr(6)
    mid = '<' + leftpart + '@' + rightpart + '>'
    return mid

def underline(char, string):
    "Return a string of char repeated len(string) times."
    string = string.rstrip('\n')
    count = len(string)
    retstr = char * count + '\n\n'
    return retstr

def file2list(filename):
    """Read a file and return each line as a list item."""
    items = []
    if os.path.isfile(filename):
        readlist = open(filename, 'r')
        for line in readlist:
            entry = line.split('#', 1)[0].rstrip()
            if entry:
                items.append(entry)
        readlist.close()
    return items

def main():
    mid = messageid('testing.invalid')
    print mid
    print underline('-', mid)
    print "Date: " + datestr()
    print "2 Hrs ago: " + hours_ago(2)


# Call main function.
if (__name__ == "__main__"):
    main()
