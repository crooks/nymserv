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
from optparse import OptionParser
import os.path
import sys
import strutils

# OptParse comes first as ConfigParser depends on it to override the path to
# the config file.
parser = OptionParser()

parser.add_option("--config", dest = "rc",
                      help = "Override .nymservrc location")
parser.add_option("-r", "--recipient", dest = "recipient",
                      help = "Recipient email address")
parser.add_option("-l", "--list", dest = "list",
                      help = "List user configuration")
parser.add_option("--cleanup", dest = "cleanup", action = "store_true",
                      default=False, help = "Perform some housekeeping")
parser.add_option("--delete", dest = "delete",
                      help = "Delete a user account and key")
parser.add_option("--process", dest = "process", action = "store_true",
                      help = "Process a maildir (Experimental")
parser.add_option("--start", dest = "start", action = "store_true",
                      help = "Start the Nymserver Daemon")
parser.add_option("--stop", dest = "stop", action = "store_true",
                      help = "Stop the Nymserver Daemon")
parser.add_option("--restart", dest = "restart", action = "store_true",
                      help = "Restart the Nymserver Daemon")

(options, args) = parser.parse_args()


# Configure the Config Parser.
config = ConfigParser.RawConfigParser()

# By default, all the paths are subdirectories of the homedir.
config.add_section('paths')
homedir = os.path.expanduser('~')
config.set('paths', 'user', os.path.join(homedir, 'users'))
config.set('paths', 'etc', os.path.join(homedir, 'etc'))
config.set('paths', 'pool', os.path.join(homedir, 'pool'))
config.set('paths', 'maildir', os.path.join(homedir, 'Maildir'))
config.set('paths', 'held', os.path.join(homedir, 'Maildir', 'held'))
config.set('paths', 'piddir', os.path.join(homedir, 'run'))
config.set('paths', 'logdir', os.path.join(homedir, 'log'))

# Logging
config.add_section('logging')
config.set('logging', 'level', 'info')

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
config.set('pgp', 'keyring', os.path.join(homedir, 'keyring'))
#config.set('pgp', 'key', 'pgpfingerprint')
#config.set('pgp', 'passphrase', 'pgppassphrase')

config.add_section('domains')
config.set('domains', 'default', 'mixnym.net')
config.set('domains', 'hosted', 'is-not-my.name, mixnym.net')

config.add_section('thresholds')
config.set('thresholds', 'daily_send_limit', 50)
config.set('thresholds', 'url_size_limit', 512 * 1024)
config.set('thresholds', 'post_size_limit', 512 * 1024)

# Try and process the .nymservrc file.  If it doesn't exist, we bailout
# as some options are compulsory.
if not options.rc:
    #configfile = os.path.join(homedir, '.nymservrc')
    #TODO This shouldn't be the default but it makes my life easier!
    configfile = os.path.join('/crypt/var/nymserv', '.nymservrc')
else:
    configfile = options.rc
if os.path.isfile(configfile):
    config.read(configfile)
else:
    sys.stdout.write("%s: Config file does not exist\n" % configfile)
    sys.exit(1)

#with open('example.cfg', 'wb') as configfile:
#    config.write(configfile)
# Here's a kludge to convert the comma-seperated string of domains into
# a list that can be interrogated.
doms = strutils.str2list(config.get('domains', 'hosted'))
config.set('domains', 'hosted', doms)

# Abort checks if required config options are not defined.
if not config.has_option('pgp', 'key'):
    sys.stdout.write("PGP key not specified in config. Aborting.\n")
    sys.exit(1)
if not config.has_option('pgp', 'passphrase'):
    logmes = "PGP passphrase not specified in config. Aborting.\n"
    sys.stdout.write(logmes)
    sys.exit(1)
