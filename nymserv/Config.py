#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 noautoindent
#
# nymserv.py - A Basic Nymserver for delivering messages to a shared mailbox
# such as alt.anonymous.messages.
#
# Copyright (C) 2012 Steve Crook <steve@mixmin.net>
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

import ConfigParser
import getpass
from optparse import OptionParser
import os
import sys
import nymserv.strutils


def makedir(d):
    """Check if a given directory exists.  If it doesn't, check if the parent
    exists.  If it does then the new directory will be created.  If not then
    sensible options are exhausted and the program aborts.

    """
    if not os.path.isdir(d):
        parent = os.path.dirname(d)
        if os.path.isdir(parent):
            os.mkdir(d, 0700)
            sys.stdout.write("%s: Directory created.\n" % d)
        else:
            msg = "%s: Unable to make directory. Aborting.\n" % d
            sys.stdout.write(msg)
            sys.exit(1)


def set_passphrase():
    """Passphrase simply contains the GnuPG Passphrase for the Nymserver's
    private key.  It can be defined in the config file but reading it on each
    startup is considered more secure.  Python is not ideal in these
    circumstances as it doesn't offer sufficiently low-level control of how
    memory is allocated.

    """
    if not config.has_option('pgp', 'passphrase'):
        msg = "%s: Enter secret passphrase: " % config.get('pgp', 'key')
        config.set('pgp', 'passphrase', getpass.getpass(msg))


# OptParse comes first as ConfigParser depends on it to override the path to
# the config file.
parser = OptionParser()

parser.add_option("--config", dest="rc",
                      help="Override .nymservrc location")
parser.add_option("-r", "--recipient", dest="recipient",
                      help="Recipient email address")
parser.add_option("-l", "--list", dest="list",
                      help="List user configuration")
parser.add_option("--cleanup", dest="cleanup", action="store_true",
                      default=False, help="Perform some housekeeping")
parser.add_option("--delete", dest="delete",
                      help="Delete a user account and key")
parser.add_option("--expire", dest="expire", action="store_true",
                      help="Delete all nyms with expired keys")
parser.add_option("--process", dest="process", action="store_true",
                      help="Process the Maildir in current console session")
parser.add_option("--start", dest="start", action="store_true",
                      help="Start the Nymserver Daemon")
parser.add_option("--stop", dest="stop", action="store_true",
                      help="Stop the Nymserver Daemon")
parser.add_option("--restart", dest="restart", action="store_true",
                      help="Restart the Nymserver Daemon")

(options, args) = parser.parse_args()


# Configure the Config Parser.
config = ConfigParser.RawConfigParser()

# By default, all the paths are subdirectories of the homedir. We define the
# actual paths after reading the config file as they're relative to basedir.
config.add_section('paths')
homedir = os.path.expanduser('~')

# Logging
config.add_section('logging')
config.set('logging', 'level', 'info')
config.set('logging', 'format', '%(asctime)s %(levelname)s %(message)s')
config.set('logging', 'datefmt', '%Y-%m-%d %H:%M:%S')
config.set('logging', 'retain', 7)

# Config options for NNTP Posting
config.add_section('nntp')
config.set('nntp', 'newsgroups', 'alt.anonymous.messages')
config.set('nntp', 'from', 'Nobody <noreply@mixnym.net>')
config.set('nntp', 'path', 'nymserv.mixmin.net!not-for-mail')
config.set('nntp', 'injectinfo', 'nymserv.mixmin.net')
config.set('nntp', 'contact', 'abuse@mixmin.net')

# hSub options
config.add_section('hsub')
config.set('hsub', 'length', 48)

# PGP options.  These are arbitrary defaults as the options must be
# provided.
config.add_section('pgp')
#config.set('pgp', 'key', 'pgpfingerprint')
#config.set('pgp', 'passphrase', 'pgppassphrase')

config.add_section('domains')
config.set('domains', 'default', 'mixnym.net')
config.set('domains', 'hosted', 'is-not-my.name, mixnym.net')

config.add_section('thresholds')
config.set('thresholds', 'daily_send_limit', 50)
config.set('thresholds', 'url_size_limit', 512 * 1024)
config.set('thresholds', 'post_size_limit', 512 * 1024)
config.set('thresholds', 'sleep_interval', 1 * 60 * 60)
config.set('thresholds', 'socket_timeout', 10)

# Miscellaneous options that don't fit other sections.
config.add_section('misc')
config.set('misc', 'recipient_source', 'X-Original-To')

#with open('example.cfg', 'wb') as configfile:
#    config.write(configfile)

# Try and process the .nymservrc file.  If it doesn't exist, we bailout
# as some options are compulsory.
if options.rc:
    configfile = options.rc
elif 'NYMSERV' in os.environ:
    configfile = os.environ['NYMSERV']
else:
    configfile = os.path.join(homedir, '.nymservrc')
if os.path.isfile(configfile):
    config.read(configfile)
else:
    sys.stdout.write("%s: Config file does not exist\n" % configfile)
    sys.exit(1)

# Now we check the directory structure exists and is valid.
if config.has_option('paths', 'basedir'):
    basedir = config.get('paths', 'basedir')
else:
    basedir = os.path.join(homedir, 'nymserv')
    config.set('paths', 'basedir', basedir)
makedir(basedir)

if not config.has_option('paths', 'etc'):
    config.set('paths', 'etc', os.path.join(basedir, 'etc'))
makedir(config.get('paths', 'etc'))

if not config.has_option('paths', 'users'):
    config.set('paths', 'users', os.path.join(basedir, 'users'))
makedir(config.get('paths', 'users'))

if not config.has_option('paths', 'pool'):
    config.set('paths', 'pool', os.path.join(basedir, 'pool'))
makedir(config.get('paths', 'pool'))

if not config.has_option('paths', 'pid'):
    config.set('paths', 'pid', os.path.join(basedir, 'run'))
makedir(config.get('paths', 'pid'))

if not config.has_option('paths', 'log'):
    config.set('paths', 'log', os.path.join(basedir, 'log'))
makedir(config.get('paths', 'log'))

if not config.has_option('paths', 'keyring'):
    config.set('paths', 'keyring', os.path.join(basedir, 'keyring'))
makedir(config.get('paths', 'keyring'))

if not config.has_option('paths', 'maildir'):
    config.set('paths', 'maildir', os.path.join(basedir, 'Maildir'))
maildir = config.get('paths', 'maildir')
makedir(maildir)
makedir(os.path.join(maildir, 'cur'))
makedir(os.path.join(maildir, 'new'))
makedir(os.path.join(maildir, 'tmp'))

if not config.has_option('paths', 'held'):
    config.set('paths', 'held', os.path.join(config.get('paths', 'maildir'),
                                             'held'))
maildir = config.get('paths', 'held')
makedir(maildir)
makedir(os.path.join(maildir, 'cur'))
makedir(os.path.join(maildir, 'new'))
makedir(os.path.join(maildir, 'tmp'))


# Here's a kludge to convert the comma-seperated string of domains into
# a list that can be interrogated.
doms = nymserv.strutils.str2list(config.get('domains', 'hosted'))
config.set('domains', 'hosted', doms)

# Abort checks if required config options are not defined.
if not config.has_option('pgp', 'key'):
    sys.stdout.write("PGP key not specified in config. Aborting.\n")
    sys.exit(1)

# Things required when running the Nymserver.
if options.start or options.process or options.restart:
    set_passphrase()
