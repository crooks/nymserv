#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 noautoindent
#
# nymserv.py - A Basic Nymserver for delivering messages to a shared mailbox
# such as alt.anonymous.messages.
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
import nntplib
import socket
import StringIO
import sys
from email.Utils import formatdate

def nntpsend(mid, content):
    payload = StringIO.StringIO(content)
    hosts = ['news.mixmin.net', 'news.glorb.com', 'newsin.alt.net']
    socket.setdefaulttimeout(10)
    for host in hosts:
        try:
            s = nntplib.NNTP(host)
        except:
            print 'Untrapped error during connect to ' + host
            continue
        try:
            s.ihave(mid, payload)
            print "%s successful IHAVE to %s." % (mid, host)
        except nntplib.NNTPTemporaryError:
            message = 'IHAVE to ' + host + ' returned a temporary error: '
            message += '%s.' % sys.exc_info()[1]
            print message
        except nntplib.NNTPPermanentError:
            message = 'IHAVE to ' + host + ' returned a permanent error: '
            message += '%s.' % sys.exc_info()[1]
            print message
        except:
            message = 'IHAVE to ' + host + ' returned an unknown error: '
            message += '%s.' % sys.exc_info()[1]
            print message
        s.quit()

def news_headers(newsgroups, subject):
    """For all messages inbound to a.a.m for a Nym, the headers are standard.
    The only required info is whether to hSub the Subject.  We expect to be
    passed an hsub value if this is required, otherwise a fake is used."""
    mid = messageid('nymserv.mixmin.net')
    message  = "Path: mail2news.mixmin.net!not-for-mail\n"
    message += "From: Anonymous <nobody@mixmin.net>\n"
    message += "Subject: " + subject + "\n"
    message += "Message-ID: " + mid + "\n"
    message += "Newsgroups: " + newsgroups + "\n"
    message += "Injection-Info: mail2news.mixmin.net\n"
    message += "Date: " + formatdate() + "\n"
    return mid, message

def middate():
    """Return a date in the format yyyymmdd.  This is useful for generating
    a component of Message-ID."""
    utctime = datetime.datetime.utcnow()
    utcstamp = utctime.strftime("%Y%m%d%H%M%S")
    return utcstamp

def datestring():
    """As per middate but only return the date element of UTC.  This is used
    for generating log and history files."""
    utctime = datetime.datetime.utcnow()
    utcstamp = utctime.strftime("%Y%m%d")
    return utcstamp

def midrand(numchars):
    """Return a string of random chars, either uc, lc or numeric.  This
    is used to provide randomness in Message-ID's."""
    randstring = ""
    while len(randstring) < numchars:
        rndsrc = random.randint(1,3)
        if rndsrc == 1:
            a = random.randint(48,57)
        elif rndsrc == 2:
            a = random.randint(65,90)
        elif rndsrc == 3:
            a = random.randint(97,122)
        randstring = randstring + chr(a)
    return randstring

def messageid(rightpart):
    """Compile a valid Message-ID.  This should never be called outside
    of testing as a message cannot reach the gateway without an ID."""
    leftpart = middate() + "." + midrand(12)
    mid = '<' + leftpart + '@' + rightpart + '>'
    return mid

def main():
    message = """Below is the PGP Public Key for the "Not My Name" Nymserver.

To use it, create a PGP key for your_desired_nym@is-not-my.name and submit it
(in ASCII plain text, unsigned and unencrypted) to config@is-not-my.name.  You
will need the server's key in order to verify the signatures on messages for
you and to encrypt configuration messages to the Nymserver.

-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.9 (GNU/Linux)

mQINBEvhQhsBEAC9iqmvTdJK3G1H/GGrgcsiATcR+id67Yqoi/ElBOTvnDE7kwmL
IpcPLS4wVKnB4S2xSOJU+nF7CxLYmFG7eCQoHiF3eSziRHt2tnSY57nzE4iU1J33
q46ZjbLAD5uGc+ZRfGrsD1+K6QFvptIQlcD9csL6Pf+1AUNvNnH/40dtkl5jQzaV
Vuo7dVZmDOyB1ClV8Zjn4MjR5XjabkzljgbKe8y4u4gMGcNaOK6pATrTRIoNwQUs
5+7PRvIqa9dqogQxs7QtoXRvY9x2aekVHK3ky9JHVKVKsn64hjKvXQADGkq/v6gk
MJH3FoG3ChR5QYHda9dgp1z/bORtqYdNF8wmjLrwia6Mw8I70cU+2hu3WWgefXMU
N5QVcrNzul/bW2OuJlBaXOHfQj30Og5zOYRYq0+pYgwAZE6lKlV7b6uIZ+XOu6Ae
6sPoseYe8uJKf+U2ltxj43rEs2Uvb0GWR1Wydo9jUXUmuqSMpzLI2ueMV8Na5nEq
jojZgZzpKFN9itkdRfq0noco2YGkaIo7PjTxUyDftHfWgtGnwxmUvuaFQ9Dslqov
KDfXcoNlPAhKCMgumMW97hbz/xMidMwJ2Im9pjx0pioSI5DmQ2fGWcvt68fyHNIl
8QBcTGwB96ItvF5NGNwumVExPhsuvdnjjwSqpFH+23EvM0qZtcLaLuxU3QARAQAB
tFZDb25maWcgaXMtbm90LW15Lm5hbWUgKENvbmZpZyBhZGRyZXNzIGZvciBJcy1O
b3QtTXkgTnltc2VydmVyKSA8Y29uZmlnQGlzLW5vdC1teS5uYW1lPokCPgQTAQIA
KAUCS+FCGwIbAwUJCWYBgAYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQ/022
YBTQxEekkg/+NtBkwKJAqykCjxlys3y1N8g2KgkOOho2PR+6pDEZvmUXEbtFDByU
K+95+bQ0V4SnuCYMFNs4rSwLESYihJ/o8NdytaQZDiYNPeKafkajBnApTuqLC/12
grHtCx9kh0v/i3s2S9pSRVySN85qtXPV/kZyUGQ4kk0rGMjVN9U1iPWYzuU6Z4AC
xIDwA0wjruoONWQbk01uTLlwTBYNcfoPIno2nMMu6/3b/nHEntoDEJ4NLiNxsvEa
glDn9RSG9FNAISEHJHbU2lpsUnGNo3FffFLUFxzhvddyvXSMZLOg1Hn2F8jpfne8
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
g8qhm8Xf9eKXWa+UzoTgOWM95w==
=AgEZ
-----END PGP PUBLIC KEY BLOCK-----
    """
    newsgroups = 'alt.privacy.anon-server.stats'
    subject = 'PGP Key for Not-My-Name Nymserver'
    mid, headers = news_headers(newsgroups, subject)
    nntpsend(mid, headers + '\n' + message)

# Call main function.
if (__name__ == "__main__"):
    main()
