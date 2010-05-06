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

import re
import email
import logging
import os.path
import datetime
import random
import sys
import nntplib
import smtplib
import socket
import StringIO
from email.Utils import formatdate
from shutil import copyfile
import gnupg
import hsub

LOGPATH = '/crypt/home/nymserv/log'
LOGLEVEL = 'debug'
USERPATH = '/crypt/home/nymserv/users'
NYMDOMAIN = 'is-not-my.name'
TMPFILE = '/crypt/home/nymserv/tmp/keyfile.tmp'
RESERVED_NYMS = ['config', 'list', 'this', 'send', 'abuse', 'admin',
                 'postmaster', 'webmaster', 'root', 'help']
SIGNKEY = '94F204C28BF00937EFC85D1AFF4DB66014D0C447'
PASSPHRASE = '3VnAyesMXmJEVSlXJMq2'

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

def underline(char, string):
    "Return a string of char repeated len(string) times."
    string = string.rstrip('\n')
    count = len(string)
    retstr = char * count + '\n\n'
    return retstr

def news_headers(hsubval = False):
    """For all messages inbound to a.a.m for a Nym, the headers are standard.
    The only required info is whether to hSub the Subject.  We expect to be
    passed an hsub value if this is required, otherwise a fake is used."""
    mid = messageid('nymserv.mixmin.net')
    message  = "Path: mail2news.mixmin.net!not-for-mail\n"
    message += "From: Anonymous <nobody@mixmin.net>\n"
    # We use an hsub if we've been passed one.
    if hsubval:
        message += "Subject: " + hsub.hash(hsubval) + '\n'
    else:
        # We use datestring as a seed for our fake hsub.
        message += "Subject: " + hsub.hash(midrand(16)) + "\n"
    message += "Message-ID: " + mid + "\n"
    message += "Newsgroups: alt.anonymous.messages\n"
    message += "Injection-Info: mail2news.mixmin.net\n"
    message += "Date: " + formatdate() + "\n"
    return mid, message

def send_success_message(recipient):
    """Post confirmation that an email was sent through the Nymserver to a
    non-anonymous recipient."""
    payload  = "Email Delivery Notification\n"
    payload += underline('-', payload)
    payload += "Your email to " + recipient + " was sent.\n"
    payload += """
Your request to send an email through the Nymserver was actioned successfully.
\n"""
    return payload

def create_success_message(addy):
    "Respond to a successful Nym create request."
    payload  = "Congratulations!\n"
    payload += underline('-', payload)
    payload += "You have registered the pseudonym " + addy + ".\n"
    payload += """
From now on, messages sent to this address will be encrypted to your key and
signed by the Nymserver before being delivered to the newsgroup
alt.anonymous.messages.

Currently your Nym has no Symmetric encryption defined.  Without this, messages
will be delivered to alt.anonymous.messages with the KeyID stripped from them.
If you would like to define a Symmetric password, send a signed and encrypted
message to config@is-not-my.name containing the following data:
Symmetric: passphrase

Likewise, an hSub Subject can be defined using:
Hsub: passphrase

Any combination of commands can be sent in the same message.  You can also
unset an option by setting it to 'none'.  E.g.
Symmetric: none

Modifications to your Nym will receive a confirmation message in
alt.anonymous.messages, formatted in accordance with your request.\n"""
    return payload

def modify_success_message(addy, conf):
    "Respond to successful Nym modification request."
    payload  = "Nym Modification Successful\n"
    payload += underline('-', payload)
    payload += "You have successfully modified you pseudonym " + addy + ".\n\n"
    payload += "After modification, the options configured on your nym are:-\n"
    for key in conf:
        payload += key + ': ' + conf[key] + '\n'
    return payload

def duplicate_message(fingerprint, addy):
    payload  = "Error - Duplicate Nym Address " + addy + ".\n"
    payload += underline('-', payload)
    payload += """
You attempted to register a Nym that already exists on the server.  You are
receiving this response because the server can send a message encrypted to
the unique key you created but external users can only send to an email
address.  Hence, the email address must be unique.\n"""
    payload += "\nThe key " + fingerprint + " "
    payload += "will now be deleted from the server.\n"
    return payload

def reserved_message(fingerprint, addy):
    payload  = 'Error - ' + addy + " is a reserved Nym.\n"
    payload += underline('-', payload)
    payload += """
You attempted to register a reserved Nym name.  You are receiving this response
because the server can send a message encrypted to the unique key you created
but the Nym will not be functional.\n"""
    payload += "\nThe key " + fingerprint + " "
    payload += "will now be deleted from the server.\n"
    return payload

def post_message(payload, conf):
    """Take a payload and add headers to it for News posting.  The dictionary
    'conf' contains specific formatting instructions."""
    mid, headers  = news_headers(conf['hsub'])
    recipient = conf['fingerprint']
    # If Symmetric encryption is specified, we don't need to throw the
    # Keyid during Asymmetric encryption.
    if conf['symmetric']:
        logger.debug('Symmetric encryption defined, not throwing KeyID')
        throwkid = False
    else:
        logger.debug('No Symmetric encryption defined, throwing KeyID')
        throwkid = True
    logger.debug('Signing and Encrypting message for ' + recipient)
    enc_payload = gnupg.signcrypt(recipient, SIGNKEY, PASSPHRASE, payload,
                                  throwkid)
    # Symmetrically wrap the payload if we have a Symmetric password defined.
    if conf['symmetric']:
        logger.debug('Adding Symmetric Encryption layer')
        enc_payload = gnupg.symmetric(conf['symmetric'], enc_payload)
    nntpsend(mid, headers + '\n' +enc_payload)

def user_read(user):
    "Read config parameters from a file."
    confopt_re = re.compile('(\w+?):\s(.+)')
    conffile = USERPATH + '/' + user + '.conf'
    if not os.path.isfile(conffile):
        error_report(401, conffile + ' cannot be opened for reading.')
    f = open(conffile, 'r')
    confdict = {}
    for line in f:
        confopt = confopt_re.match(line)
        if confopt:
            key = confopt.group(1).lower()
            value = confopt.group(2)
            # We make special cases for writing True or False to dict values.
            if value.lower() == 'false':
                confdict[key] = False
            else:
                confdict[key] = value
    f.close()
    return confdict

def user_write(user, confdict):
    "Write an updated user conf file."
    conffile = USERPATH + '/' + user + '.conf'
    oldfile = conffile + '.old'
    if os.path.isfile(conffile):
        logger.debug('Creating backup file ' + oldfile)
        copyfile(conffile, oldfile)
        logger.info('Updating user config file for ' + user)
    else:
        logger.info('Creating user config file for ' + user)
    f = open(conffile, 'w')
    for key in confdict:
        value = confdict[key]
        if not value:
            line = key + ': False\n'
        else:
            line = key + ': ' + value + '\n'
        f.write(line)
    must_have_keys = ['fingerprint', 'hsub', 'symmetric']
    for key in must_have_keys:
        if not key in confdict:
            message = 'Somehow must-have key ' + key + ' is not in user conf.'
            message += ' Setting it to False, (although this may be silly).'
            logger.warn(message)
            line = key + ': False\n'
            f.write(line)
    f.close()

def user_update(confdict, text):
    """Update a user's config paramters from a text body. The current list of
    options is read from confdict and updated with those in the text.  To use
    this function, confdict must already be populated using user_read."""
    locked_keys = ['fingerprint']
    confopt_re = re.compile('(\w+?):\s(.+)')
    lines = text.split('\n')
    for line in lines:
        confopt = confopt_re.match(line)
        if confopt:
            # Set key to the key name and value to its content.
            key = confopt.group(1).lower()
            value = confopt.group(2)
            # Some keys are not user definable.
            if key in locked_keys:
                logger.info('Ignoring request to modify locked Key: ' + key)
            else:
                # None or False means set the key to False.
                if value.lower() == 'none' or value.lower() == 'false':
                    confdict[key] = False
                else:
                    if key in confdict:
                        logger.info('Updating ' + key + ' option.')
                    else:
                        logger.info('Creating ' + key + ' option.')
                    confdict[key] = value
    return confdict

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

def key_or_message(text):
    """Identify if the payload we're processing is in plain-text, a public Key
    or an encrypted message."""
    if '-----BEGIN PGP PUBLIC KEY BLOCK-----' in text \
    and '-----END PGP PUBLIC KEY BLOCK-----' in text:
        return 001, 'key'
    if '-----BEGIN PGP MESSAGE-----' in text \
    and '-----END PGP MESSAGE-----' in text:
        return 001, 'message'
    return 001, 'text'

def key_to_file(text, file):
    lines = text.split('\n')
    f = open(file, 'w')
    inblock = False
    for line in lines:
        if line == '-----BEGIN PGP PUBLIC KEY BLOCK-----':
            inblock = True
        if inblock:
            f.write(line + '\n')
        if line == '-----END PGP PUBLIC KEY BLOCK-----':
            inblock = False
    f.close()
    return 101, 'Keybock successfully written to ' + file

def split_email_domain(address):
    "Return the two parts of an email address"
    left, right = address.split('@', 1)
    return left, right

def msgparse(message):
    "Parse a received email."
    # nymlist willl contain a list of all the nyms currently on the server
    rc, nymlist = gnupg.emails_to_list()
    # Use the email library to create the msg object.
    msg = email.message_from_string(message)
    if not 'X-Original-To' in msg:
        error_report(501, 'Message contains no X-Original-To header.')
    xot_email = msg['X-Original-To']
    xot_addy, xot_domain = split_email_domain(xot_email)
    logger.info('Processing received email message for: ' + xot_email)
    if xot_domain <> NYMDOMAIN:
        error_report(501, 'Received message for invalid domain: ' + xot_domain)
    body = msg.get_payload(decode=1)
    if not body:
        error_report(301, 'Empty message payload.')

    # Start of the functionality for creating new Nyms.
    # Who was this message sent to?
    if xot_addy == 'config':
        # Next we want to check if we're receiving a message or a Public Key.
        rc, kom = key_or_message(body)
        # If it's a key then this can only be a new Nym request.
        if kom == 'key':
            logger.debug('Processing a new Nym request.')
            # Write any valid looking keyblock data to a tmp file.
            rc, result = key_to_file(body, TMPFILE)
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
                message = reserved_message(fingerprint, key_email)
                conf = {'fingerprint' : fingerprint,
                        'hsub' : False,
                        'symmetric' : False}
                post_message(message, conf)
                logger.info('Deleting key ' + fingerprint)
                gnupg.delete_key(fingerprint)
                error_report(301, key_addy + ' is a reserved Nym.')
            # Check if we already have a Nym with this address.
            if key_addy in nymlist:
                message = duplicate_message(fingerprint, key_email)
                # We need to create a fake user config as this isn't a real
                # Nym holder.
                conf = {'fingerprint' : fingerprint,
                        'hsub' : False,
                        'symmetric' : False}
                post_message(message, conf)
                logger.info('Deleting key ' + fingerprint)
                gnupg.delete_key(fingerprint)
                error_report(301, 'Nym ' + key_addy + ' already exists.')
            # If script execution gets here, we know we're dealing with an
            # accepted new Nym.
            conf = {'fingerprint' : fingerprint,
                    'hsub' : False,
                    'symmetric' : False}
            user_write(key_addy, conf)
            f = open(USERPATH + '/' + key_addy + '.key', 'w')
            f.write(gnupg.export(fingerprint) + '\n') 
            f.close()
            logger.info('Nym ' + key_addy + ' successfully created.')
            message = create_success_message(key_addy)
            post_message(message, conf)
        # If we've received a PGP Message to our config address, it can only
        # be a signed and encrypted request to modify a Nym config.
        elif kom == 'message':
            logmessage = 'This email is a PGP Message. Assuming its a modify request.'
            logger.debug(logmessage)
            rc, mod_email, content = gnupg.verify_decrypt(body, PASSPHRASE)
            error_report(rc, mod_email)
            logger.debug('Modify Nym request is for ' + mod_email + '.')
            mod_addy, mod_domain = split_email_domain(mod_email)
            # We get the user conf dictionary from user_read.
            conf = user_read(mod_addy)
            # User conf is updated by passing a plain text block of
            # key: options to user_update.
            conf = user_update(conf, content)
            # Finally we write the updated user config back to its text file.
            user_write(mod_addy, conf)
            message = modify_success_message(mod_addy, conf)
            post_message(message, conf)
        else:
            error_report(301, 'Not key or encrypted message.')

    # We also send messages for Nymholders after verifying their signature.
    elif xot_addy == 'send':
        logger.debug('Message received for forwarding.')
        if not 'Recipient' in msg:
            error_report(301, 'No Recipient header on Send message.')
        rc, nym_email = gnupg.verify(body)
        error_report(rc, nym_email)
        logger.info('Valid signature on Send message from ' + nym_email + '.')
        nym_addy, nym_domain = split_email_domain(nym_email)
        email_message  = 'From: ' + nym_email + '\n'
        email_message += 'To: ' + msg['Recipient'] + '\n'
        wanted_headers = ['Subject', 'Message-ID', 'Date', 'Newsgroups']
        for header in wanted_headers:
            if header in msg:
                email_message += header +  ': ' + msg[header] + '\n'
        email_message += '\n' + body
        logger.debug('Attempting to email message to ' + msg['recipient'])
        server = smtplib.SMTP('localhost')
        #server.set_debuglevel(1)
        try:
            server.sendmail(nym_email, msg['Recipient'], email_message)
        except:
            message = 'Sending email failed with: %s.' % sys.exc_info()[1]
            error_report(401, message)
        server.quit()
        message = send_success_message(msg['Recipient'])
        conf = user_read(nym_addy)
        post_message(message, conf)

    # If the message isn't to config, it's a message to a Nym.
    else:
        if not xot_addy in nymlist:
            error_report(301, 'No public key for ' + xot_email + '.')
        logger.debug("Processing plain-text message to " + xot_addy)
        message = ''
        wanted_headers = ['From', 'Subject', 'Message-ID', 'Reply-To',
                          'References', 'In-Reply-To']
        for header in wanted_headers:
            if header in msg:
                message += header + ': ' + msg[header] + '\n'
        message += '\n' + body
        # Attempt to encrypt and sign the payload
        conf = user_read(xot_addy)
        post_message(message, conf)

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
    hosts = ['news.mixmin.net', 'news.glorb.com', 'newsin.alt.net']
    socket.setdefaulttimeout(10)
    for host in hosts:
        logger.debug('Posting to ' + host)
        try:
            s = nntplib.NNTP(host)
        except:
            logger.warn('Untrapped error during connect to ' + host)
            continue
        try:
            s.ihave(mid, payload)
            logger.info("%s successful IHAVE to %s." % (mid, host))
        except nntplib.NNTPTemporaryError:
            message = 'IHAVE to ' + host + ' returned a temporary error: '
            message += '%s.' % sys.exc_info()[1]
            logger.info(message)
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
    "Initialize logging functions, then process messages piped to stdin."
    init_logging()
    sys.stdout.write("Type message here.  Finish with Ctrl-D.\n")
    msgparse(sys.stdin.read())

# Call main function.
if (__name__ == "__main__"):
    main()
