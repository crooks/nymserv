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

from email.Utils import formatdate
import strutils
import ihave

def news_headers(newsgroups, subject):
    """For all messages inbound to a.a.m for a Nym, the headers are standard.
    The only required info is whether to hSub the Subject.  We expect to be
    passed an hsub value if this is required, otherwise a fake is used."""
    mid = strutils.messageid('nymserv.mixmin.net')
    message  = "Path: mail2news.mixmin.net!not-for-mail\n"
    message += "From: Anonymous <nobody@mixmin.net>\n"
    message += "Subject: " + subject + "\n"
    message += "Message-ID: " + mid + "\n"
    message += "Newsgroups: " + newsgroups + "\n"
    message += "Injection-Info: mail2news.mixmin.net\n"
    message += "Date: " + formatdate() + "\n"
    return mid, message

def main():
    message = """Below is the PGP Public Key for the "Not My Name" Nymserver.

To use it, create a PGP key for your_desired_nym@is-not-my.name and submit it
(in ASCII plain text, unsigned and unencrypted) to config@is-not-my.name.  You
will need the server's key in order to verify the signatures on messages for
you and to encrypt configuration messages to the Nymserver.

-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.9 (GNU/Linux)

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
=+TpS
-----END PGP PUBLIC KEY BLOCK-----
    """
    newsgroups = 'alt.privacy.anon-server.stats'
    subject = 'PGP Key for Not-My-Name Nymserver'
    mid, headers = news_headers(newsgroups, subject)
    ihave.send(mid, headers + '\n' + message)

# Call main function.
if (__name__ == "__main__"):
    main()
