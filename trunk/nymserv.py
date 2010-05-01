#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 noautoindent
#
# m2n.py -- This is a simple mail2news script that accepts messages formatted
# with a Newsgroups header or delivered to a recipient in the format
# mail2news-yyyymmdd-news.group@domain.com
#
# Copyright (C) 2008 Steve Crook <steve@mixmin.net>
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

import re
import email
import logging
import os.path
import datetime
import sys
import random
import nntplib
import StringIO
from email.Utils import formatdate
from optparse import OptionParser
import gnupg

LOGPATH = '/home/nymtest/log'
LOGLEVEL = 'debug'
NYMDOMAIN = 'nymtest.mixmin.net'
TMPFILE = '/home/nymtest/keyfile.tmp'
RESERVED_NYMS = ['config', 'list']
SIGNKEY = 'E15017369A622591FA95A5289DDE38992134085B'
PASSPHRASE = '4mgCwmJrMs/c3RJadX2a'

def init_logging():
    """Initialise logging.  This should be the first thing done so that all
    further operations are logged."""
    loglevels = {'debug': logging.DEBUG, 'info': logging.INFO,
                'warn': logging.WARN, 'error': logging.ERROR}
    global logger
    logger = logging.getLogger('m2n')
    logpath = LOGPATH.rstrip("/")
    logfile = datestring()
    filename = "%s/%s" % (logpath, logfile)
    try:
        hdlr = logging.FileHandler(filename)
    except IOError:
        print "Error: Unable to initialize logger.  Check file permissions?"
        sys.exit(1)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    level = loglevels[LOGLEVEL]
    logger.setLevel(level)

def success_message(fingerprint, addy):
    mid = messageid(NYMDOMAIN)
    message  = "Path: " + NYMDOMAIN + "!not-for-mail\n"
    message += "From: Test Nymserver <nobody@mixmin.net>\n"
    message += "Subject: Confirmation for " + addy + "\n"
    message += "Message-ID: " + mid + "\n"
    message += "Newsgroups: alt.anonymous.messages\n"
    message += "Injection-Info: " + NYMDOMAIN + "\n"
    message += "Date: " + formatdate() + "\n"
    message += "\n"
    payload  = "Congratulations!\n"
    payload += "You have registered the pseudonym " + addy + ".\n"
    payload += """
From now on, messages sent to this address will be encrypted to your key and
signed by the Nymserver before being delivered to the newsgroup
alt.anonymous.messages.\n"""
    enc_payload = gnupg.signcrypt(fingerprint, SIGNKEY, PASSPHRASE, payload)
    nntpsend(mid, message + enc_payload)

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
    utcstamp = utctime.strftime("%Y-%m-%d")
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

def split_email_domain(address):
    "Return the two parts of an email address"
    left, right = address.split('@', 1)
    return left, right

def msgparse(message):
    "Parse a received email."
    # nymlist willl contain a list of all the nyms currently on the server
    nymlist = gnupg.emails_to_list()
    # Use the email library to create the msg object.
    msg = email.message_from_string(message)
    # Who was this message sent to?  It needs to be configure@nymdomain
    if 'X-Original-To' in msg:
        xot_email = msg['X-Original-To']
        xot_addy, xot_domain = split_email_domain(xot_email)
        logger.debug('Message recipient is: ' + xot_addy)
    else:
        error_report(501, 'Message contains no X-Original-To header.')
    if xot_domain <> NYMDOMAIN:
        error_report(501, 'Received message for invalid domain: ' + xot_domain)
    body = msg.get_payload(decode=1)
    # Start of the functionality for creating new Nyms.
    if xot_addy == 'config':
        logger.info('Message sent to config address.')
        # Write any valid looking keyblock data to a tmp file.
        rc, result = gnupg.key_to_file(body, TMPFILE)
        error_report(rc, result)
        # Try to import the valid looking keyblock.
        rc, fingerprint = gnupg.import_file(TMPFILE)
        error_report(rc, fingerprint)
        logger.info('Imported key ' + fingerprint)
        # If we've managed to import a key, get the email address from it.
        rc, key_email = gnupg.get_email_from_keyid(fingerprint)
        error_report(rc, key_email)
        logger.info('Extracted ' + key_email + ' from ' + fingerprint)
        # Split out the address and domain components of the email address
        key_addy, key_domain = split_email_domain(key_email)
        # Simple check to ensure the key is in the right domain.
        if key_domain <> NYMDOMAIN:
            logger.info('Deleting key ' + fingerprint)
            gnupg.delete_key(fingerprint)
            error_report(301, 'Wrong domain on ' + key_email + '.')
        # Simple check to ensure the nym isn't on the reserved list.
        if key_addy in RESERVED_NYMS:
            logger.info('Deleting key ' + fingerprint)
            gnupg.delete_key(fingerprint)
            error_report(301, key_addy + ' is a reserved Nym.')
        # Check if we already have a Nym with this address.
        # TODO We can send a reply to the key before deleting it
        if key_addy in nymlist:
            logger.info('Deleting key ' + fingerprint)
            gnupg.delete_key(fingerprint)
            error_report(301, 'Nym ' + key_addy + ' already exists.')
        logger.info('Nym ' + key_addy + ' successfully created.')
        success_message(fingerprint, key_email)

    # If the message isn't to config, it's a message to a Nym
    else:
        if not xot_addy in nymlist:
            error_report(301, 'No public key for ' + xot_email)
        logger.debug("Processing message to " + recipient)
        payload = ''
        wanted_headers = ['From', 'Subject', 'Message-ID', 'Reply-To']
        for header in wanted_headers:
            if header in msg:
                payload += header + ': ' + msg[header] + "\n"
        payload += '\n' + body
        # Attempt to encrypt and sign the payload
        enc_payload = gnupg.signcrypt(xot_email, SIGNKEY, PASSPHRASE, payload)
        mid = messageid(NYMDOMAIN)
        message  = "Path: " + NYMDOMAIN + "!not-for-mail\n"
        message += "From: Test Nymserver <nobody@mixmin.net>\n"
        message += "Subject: " + xot_email + "\n"
        message += "Message-ID: " + mid + "\n"
        message += "Newsgroups: alt.anonymous.messages\n"
        message += "Injection-Info: " + NYMDOMAIN
        message += "Date: " + formatdate() + "\n"
        message += "\n"
        logger.debug('Attempting to deliver message for ' + xot_email)
        nntpsend(mid, message + enc_payload)

def error_report(rc, desc):
    # 000   Success, no message
    # 100   Success, debug message
    # 200   Success, info message
    # 300   Fail, Info message
    # 400   Fail, Warn message
    # 500   Fail, Error message
    if rc >= 100 and rc < 200:
        logger.debug(desc)
    if rc >= 200 and rc < 300:
        logger.info(desc)
    if rc >= 300 and rc < 400:
        logger.info(desc + ' Aborting')
        sys.exit(rc)
    if rc >= 400 and rc < 500:
        logger.warn(desc + ' Aborting')
        sys.exit(rc)
    if rc >=500 and rc < 600:
        logger.error(desc + ' Aborting')
        sys.exit(rc)

def nntpsend(mid, content):
    payload = StringIO.StringIO(content)
    hosts = ['news.mixmin.net', 'news.glorb.com']
    for host in hosts:
        logger.debug('Posting to ' + host)
        s = nntplib.NNTP(host)
        try:
            s.ihave(mid, payload)
            logger.info("%s successful IHAVE to %s." % (mid, host))
        except nntplib.NNTPTemporaryError:
            message = 'IHAVE to ' + host + ' returned a temporary error: '
            message += '%s.' % sys.exc_info()[1]
            logger.warn(message)
        except nntplib.NNTPPermanentError:
            message = 'IHAVE to ' + host + ' returned a permanent error: '
            message += '%s.' % sys.exc_info()[1]
            logger.warn(message)
        except:
            message = 'IHAVE to ' + host + ' returned an unknown error: '
            message += '%s.' % sys.exc_info()[1]
            logger.warn(message)
        s.quit()

def main():
    """Initialize the options parser and logging functions, then process
    messages piped to stdin."""
    #global options
    #(options, args) = init_parser()
    init_logging()
    sys.stdout.write("Type message here.  Finish with Ctrl-D.\n")
    msgparse(sys.stdin.read())

# Call main function.
if (__name__ == "__main__"):
    main()
