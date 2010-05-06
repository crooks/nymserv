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

from hashlib import sha256
from os import urandom

HSUBLEN = 48

def hash(text, iv = None, hsublen = HSUBLEN):
    """Create an hSub (Hashed Subject). This is constructed as:
    --------------------------------------
    | 64bit iv | 256bit SHA2 'iv + text' |
    --------------------------------------"""
    # Generate a 64bit random IV if none is provided.
    if iv is None: iv = cryptorandom()
    # Concatenate our IV with a SHA256 hash of text + IV.
    hsub = iv + sha256(iv + text).digest()
    return hsub.encode('hex')[:hsublen]

def check(text, hsub):
    """Create an hSub using a known iv, (stripped from a passed hSub).  If
    the supplied and generated hSub's collide, the message is probably for
    us."""
    # We are prepared to check variable length hsubs within boundaries.
    # The low bound is the current Type-I esub length.  The high bound
    # is the 256 bits within SHA2-256.
    hsublen = len(hsub)
    # 48 digits = 192 bit hsub, the smallest we allow.
    # 80 digits = 320 bit hsub, the full length of SHA256 + 64 bit IV
    if hsublen < 48 or hsublen > 80: return False
    iv = hexiv(hsub)
    if not iv: return False
    # Return True if our generated hSub collides with the supplied
    # sample.
    return hash(text, iv, hsublen) == hsub

def cryptorandom(bytes = 8):
    """Return a string of random bytes. By default we return the default
    IV length (64bits)."""
    return urandom(bytes)

def hexiv(hsub, digits = 16):
    """Return the decoded IV from an hsub.  By default the IV is the first
    64bits of the hsub.  As it's hex encoded, this equates to 16 digits."""
    # We don't want to process IVs of inadequate length.
    if len(hsub) < digits: return False
    try:
        iv = hsub[:digits].decode('hex')
    except TypeError:
        # Not all Subjects are hSub'd so just bail out if it's non-hex.
        return False
    return iv

def main():
    """Only used for testing purposes.  We Generate an hSub and then check it
    using the same input text."""
    text = cryptorandom()
    hsub = hash(text)
    iv = hexiv(hsub)
    print "hsub: " + hsub
    print "IV:   %s" % iv.encode('hex')
    print "hsub length: %d bytes" % len(hsub)
    print "IV Length:   %2d bytes" % len(iv)
    print "Should return True:  %s" % check(text, hsub)
    print "Should return False: %s" % check('false', hsub)

# Call main function.
if (__name__ == "__main__"):
    main()
