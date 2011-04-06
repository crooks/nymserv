#!/usr/bin/env python
#
# vim: tabstop=4 expandtab shiftwidth=4 noautoindent
#
# batch.py - Newsserver injection batch processing
#
# Copyright (C) 2011 Steve Crook <steve@mixmin.net>
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

from daemon import Daemon
from email.parser import Parser
from time import sleep
import logging
import nntplib
import os
import os.path
import socket
import strutils
import sys

LOGLEVEL = 'debug'
HOMEDIR = os.path.expanduser('~')
LOGPATH = os.path.join(HOMEDIR, 'log')
PIDPATH = os.path.join(HOMEDIR, 'run')
ETCPATH = os.path.join(HOMEDIR, 'etc')
POOLPATH = os.path.join(HOMEDIR, 'pool')

class MyDaemon(Daemon):
    def run(self):
        while True:
            rc = p.pool_process()
            sleep(1800)

class pool:
    def __init__(self):
        hostfile = os.path.join(ETCPATH, 'newsservers')
        if not os.path.isfile(hostfile):
            logging.error('%s: Peers file does not exist' % hostfile)
            sys.exit(1)
        self.hosts = strutils.file2list(hostfile)
        if len(self.hosts) == 0:
            logging.error('No news peers defined.')
            sys.exit(1)
        socket.setdefaulttimeout(10)

    def listdir(self, path):
        """Return a list of files in the Pool dir."""
        if os.path.isdir(path):
            return os.listdir(path)
        else:
            logging.error('%s: Pool directory does not exist' % path)
            sys.exit(1)

    def connect_peers(self):
        peers = {}
        # Establish connections with all of our newsservers
        for host in self.hosts:
            logging.debug('Connecting to %s' % host)
            try:
                peers[host] = nntplib.NNTP(host)
                #peers[host].set_debuglevel(2)
                logging.debug('%s: Connection established' % host)
            except:
                logging.warn('Untrapped error during connect to %s' % host)
                continue
        return peers

    def pool_process(self):
        pool_files = self.listdir(POOLPATH)
        # If the pool has no files in it, we don't need to do anything.
        num_pool_files = len(pool_files)
        if num_pool_files == 0:
            logging.info('No files in pool to process so no action required.')
            return 0;
        logging.debug('Processing %s pool files' % num_pool_files)
        peers = self.connect_peers()

        # If there are no host connections, log it and give up.
        if len(peers) == 0:
            logmes  = 'Aborting: All %s peer connections' % len(self.hosts)
            logmes += ' failed. Check Internet connection, it might be dead.'
            logging.warn(logmes)
            return 1;

        # Iterate through all the files in the pool
        for filename in pool_files:
             # Bool set to true is any newsserver accepts the post
            success = False
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

            # Now we offer the message to our peers and hope at least one
            # accepts.
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
        for host in peers:
            peers[host].quit()
            logging.debug('%s: Connection Closed' % host)
        # Processing completed normally.
        return 0;

def init_logging():
    loglevels = {'debug': logging.DEBUG, 'info': logging.INFO,
                'warn': logging.WARN, 'error': logging.ERROR}
    logfile = os.path.join(LOGPATH, 'test-' + strutils.datestr())
    logging.basicConfig(
        filename=logfile,
        level = loglevels[LOGLEVEL],
        format = '%(asctime)s %(process)d %(levelname)s %(message)s',
        datefmt = '%Y-%m-%d %H:%M:%S')

if __name__ == "__main__":
    init_logging()
    if not os.path.isdir(PIDPATH):
        sys.stdout.write('PID directory %s does not exist\n' % PIDPATH)
        sys.exit(1)
    pidfile = os.path.join(PIDPATH, 'batch.pid')
    p = pool()
    daemon = MyDaemon(pidfile, '/dev/null', '/dev/null', LOGPATH + '/err')
    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            daemon.start()
        elif 'stop' == sys.argv[1]:
            daemon.stop()
        elif 'restart' == sys.argv[1]:
            daemon.restart()
        else:
            print "Unknown command"
            sys.exit(2)
        sys.exit(0)
    else:
        print "usage: %s start|stop|restart" % sys.argv[0]
        sys.exit(2)
