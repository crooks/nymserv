#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 autoindent
#
# Copyright (C) 2011 Steve Crook <steve@mixmin.net>
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


class HSub():
    def __init__(self, trimchars=48, ivchars=8):
        # The length in Bytes of the IV
        self.trimchars = trimchars
        self.ivchars = ivchars

    def hash(self, secret, iv=None, length=None):
        """Create an hSub (Hashed Subject). This is constructed as:
        ----------------------------------
        | iv | 256bit SHA2 'iv + secret' |
        ----------------------------------
        In all known implementations, iv=64 bits
        The hSub may be trimmed to "length".  By default this is
        currently 48 chars in order to match eSub.

        """
        # Generate a random IV if none is provided.
        if iv is None:
            iv = self.cryptorandom(self.ivchars)
        if length is None:
            length = self.trimchars
        # Concatenate our IV with a SHA256 hash of text + IV.
        hsub = iv + sha256(iv + secret).digest()
        return hsub.encode('hex')[:length]

    def check(self, secret, hsub):
        """Create an hSub using a known iv, (stripped from a passed hSub).  If
        the supplied and generated hSub's collide, the message is probably for
        us.

        """
        iv = self.hexiv(hsub)
        if not iv:
            return False
        # Return True if our generated hSub collides with the supplied
        # sample.
        return self.hash(secret, iv, len(hsub)) == hsub

    def cryptorandom(self, numbytes):
        """Return a string of random bytes.

        """
        return urandom(numbytes)

    def hexiv(self, hsub):
        """Return the decoded IV from an hsub.  By default the IV is the first
        64bits of the hsub.  As it's hex encoded, this equates to 16 digits.

        """
        # Hex digits are twice the Byte length
        digits = self.ivchars * 2
        try:
            iv = hsub[:digits].decode('hex')
        except TypeError:
            # Not all Subjects are hSub'd so just bail out if it's non-hex.
            return False
        return iv


def main():
    """Only used for testing purposes.  We Generate an hSub and then check it
    using the same input text.

    """
    hsub = HSub(48, 8)
    passphrase = "passphrase"
    sub = hsub.hash(passphrase)
    iv = hsub.hexiv(sub)
    print "Passphrase: " + passphrase
    print "IV:   %s" % iv.encode('hex')
    print "hsub: " + sub
    print "hsub length: %d bytes" % len(sub)
    print "iv length: %d bytes" % len(iv)
    print "Should return True:  %s" % hsub.check(passphrase, sub)
    print "Should return False: %s" % hsub.check('false', sub)

# Call main function.
if (__name__ == "__main__"):
    main()
