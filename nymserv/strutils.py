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
import textwrap


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

def pool_filename(prefix):
    """File naming format for pool files."""
    return str(prefix) + datetimestr() + '.' + randstr(6)

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

def file2text(filename, conf):
    """Read a file a return it as a tidied string. Paragraphs in the file
    that end with a # will be wrapped."""
    f = open(filename, 'r')
    s = f.read() % conf
    f.close()
    paras = s.split('\n\n')
    payload = ''
    for p in paras:
        p = p.rstrip()
        if p.endswith('#'):
            payload += textwrap.fill(p[:-1], 72) + '\n\n'
        else:
            payload += p + '\n\n'
    return payload.rstrip()

def str2list(string):
    """Take a comma-seperated string and return it as a list, with leading and
    trailing spaces removed from each item."""
    items = string.split(',')
    newitems = []
    for i in items:
        newitems.append(i.strip())
    return newitems

def optparse(txt):
    """URL opt/val arguements were originally defined as 'opt val' instead of
    the standard 'opt: val'.  To address this, we look for whether space or
    colon occurs first (on the principle that opt cannot contain a space).
    We split them at the first occurance of space or colon."""
    space = txt.find(" ")
    colon = txt.find(":")
    # If there is no space, find returns -1.  We therefore need to check
    # that space is in fact positive.  We also ignore space=0 so that leading
    # spaces are not treated as a seperator.
    if space > 0 and (space < colon or colon < 0):
        o, v = txt.split(" ", 1)
    elif colon > 0:
        o, v = txt.split(":", 1)
    else:
        return None, None
    o = o.strip().lower()
    v = v.strip()
    return o, v

def main():
    s = 'opt: val'
    print optparse(s)

# Call main function.
if (__name__ == "__main__"):
    main()
