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
import os
import os.path
from email.parser import Parser

import strutils

HOMEDIR = os.path.expanduser('~')
ETCPATH = os.path.join(HOMEDIR, 'etc')
POOLPATH = os.path.join(HOMEDIR, 'pool')

def poollist():
    return os.listdir(POOLPATH)

def pool_process():
    pool_files = poollist()
    # If the pool has no files in it, we don't need to do anything.
    if len(pool_files) == 0:
        logging.info('No files in pool to process so no action required.')
        sys.exit(0)
    hostfile = os.path.join(ETCPATH, 'newsservers')
    hosts = strutils.file2list(hostfile)
    if len(hosts) == 0:
        logging.warn('No news peers defined.')
    socket.setdefaulttimeout(10)
    peers = {}
    # Establish connections with all of our newsservers
    for host in hosts:
        logging.debug('Connecting to %s' % host)
        try:
            peers[host] = nntplib.NNTP(host)
            #peers[host].set_debuglevel(2)
            logging.debug('%s: Connection established' % host)
        except:
            logging.warn('Untrapped error during connect to %s' % host)
    # Iterate through all the files in the pool
    for filename in pool_files:
        success = False # Bool set to true is any newsserver accepts the post
        # Create a fully-qualified filename to avoid any confusion
        fqname = os.path.join(POOLPATH, filename)
        f = open(fqname, 'r')

        # We have to perform this tiresome step in order to pass the
        # Message-ID to our peers during IHAVE.
        msg = Parser().parse(f, 'headersonly')
        if 'Message-ID' in msg:
            mid = msg['Message-ID']
            logging.debug('%s: Contains Message-ID: %s' % (filename, mid))
        else:
            logging.warn('%s: Contains no Message-ID. Skipping.' % fqname)
            continue

        # Now we offer the message to our peers and hope at least one accepts.
        for host in peers:
            f.seek(0) # Start from the beginning of our file
            try:
                peers[host].ihave(mid, f)
                success = True
                logging.info('%s: Accepted %s' % (host, mid))
            except nntplib.NNTPTemporaryError:
                message = '%s: IHAVE returned a temporary error: ' % host
                message += '%s.' % sys.exc_info()[1]
                logging.info(message)
            except nntplib.NNTPPermanentError:
                message = '%s: IHAVE returned a permanent error: ' % host
                message += '%s.' % sys.exc_info()[1]
                logging.warn(message)
            except:
                message = 'IHAVE returned an unknown error: '
                message += '%s.' % sys.exc_info()[1]
                logging.warn(message)
        # Close the file object
        f.close()

        # Check the success flag.  If True we can delete the file from the
        # pool.  If not, log it.
        if success:
            os.remove(fqname)
            logging.info('%s: Deleted from pool' % filename)
        else:
            logging.warn('%s: Not accepted. Retaining in pool' % filename)

    # Finally close the connections to our peers.
    for host in hosts:
        peers[host].quit()
        logging.debug('%s: Connection Closed' % host)

def main():
    logging.basicConfig(
        stream=sys.stdout,
        level = logging.DEBUG,
        format = '%(asctime)s %(process)d %(levelname)s %(message)s',
        datefmt = '%Y-%m-%d %H:%M:%S')
    pool_process()

# Call main function.
if (__name__ == "__main__"):
    main()
