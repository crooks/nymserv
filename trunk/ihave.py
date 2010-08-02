#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 noautoindent
#
# ihave.py - Newsserver injector
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

import nntplib
import socket
import cStringIO
import logging
import sys

def send(mid, content):
    payload = cStringIO.StringIO(content)
    hosts = ['news.glorb.com', 'newsin.alt.net', 'localhost']
    socket.setdefaulttimeout(10)
    for host in hosts:
        # Reset the File pointer to the beginning.
        payload.seek(0)
        logging.debug('Posting to ' + host)
        try:
            s = nntplib.NNTP(host)
            #s.set_debuglevel(2)
        except:
            logging.warn('Untrapped error during connect to ' + host)
            continue
        try:
            s.ihave(mid, payload)
            logging.info("%s successful IHAVE to %s." % (mid, host))
        except nntplib.NNTPTemporaryError:
            message = 'IHAVE to ' + host + ' returned a temporary error: '
            message += '%s.' % sys.exc_info()[1]
            logging.info(message)
        except nntplib.NNTPPermanentError:
            message = 'IHAVE to ' + host + ' returned a permanent error: '
            message += '%s.' % sys.exc_info()[1]
            logging.warn(message)
        except:
            message = 'IHAVE to ' + host + ' returned an unknown error: '
            message += '%s.' % sys.exc_info()[1]
            logging.warn(message)
        s.quit()
    payload.close()

def main():
    import strutils
    from email.utils import formatdate
    logging.basicConfig(
        stream=sys.stdout,
        level = logging.DEBUG,
        format = '%(asctime)s %(process)d %(levelname)s %(message)s',
        datefmt = '%Y-%m-%d %H:%M:%S')
    mid = strutils.messageid('testing.mixmin.net')
    message  = "Path: testing.mixmin.net!not-for-mail\n"
    message += "Message-ID: " + mid + "\n"
    message += "From: Testing <testing@testing.mixmin.net>\n"
    message += "Subject: Testing\n"
    message += "Newsgroups: alt.testing.testing\n"
    message += "Date: " + formatdate() + "\n"
    message += "\nTesting"
    send(mid, message)

# Call main function.
if (__name__ == "__main__"):
    main()
