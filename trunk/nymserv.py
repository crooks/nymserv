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
import email.utils
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from shutil import copyfile
import gnupg
import hsub
import urlfetch

LOGPATH = '/crypt/home/nymserv/log'
LOGLEVEL = 'debug'
USERPATH = '/crypt/home/nymserv/users'
NYMDOMAIN = 'is-not-my.name'
TMPFILE = '/crypt/home/nymserv/tmp/keyfile.tmp'
RESERVED_NYMS = ['config', 'list', 'this', 'send', 'abuse', 'admin',
                 'postmaster', 'webmaster', 'root', 'help', 'url']
SIGNKEY = '94F204C28BF00937EFC85D1AFF4DB66014D0C447'
PASSPHRASE = '3VnAyesMXmJEVSlXJMq2'

def init_logging():
    loglevels = {'debug': logging.DEBUG, 'info': logging.INFO,
                'warn': logging.WARN, 'error': logging.ERROR}
    logpath = LOGPATH.rstrip("/")
    logfile = datestring()
    pathfile = "%s/%s" % (logpath, logfile)
    logging.basicConfig(
        filename=pathfile,
        level = loglevels[LOGLEVEL],
        format = '%(asctime)s %(process)d %(levelname)s %(message)s',
        datefmt = '%Y-%m-%d %H:%M:%S')

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
        hash = hsub.hash(hsubval)
        message += "Subject: " + hash + '\n'
        logging.debug("Generated a real hSub: " + hash)
    else:
        hash = hsub.cryptorandom(24).encode('hex')
        message += "Subject: " + hash + "\n"
        logging.debug("Fake hSub: " + hash)
    message += "Message-ID: " + mid + "\n"
    message += "Newsgroups: alt.anonymous.messages\n"
    message += "Injection-Info: mail2news.mixmin.net; "
    message += "mail-complaints-to=\"abuse@mixmin.net\"\n"
    message += "Date: " + email.utils.formatdate() + "\n"
    return mid, message

def send_success_message(msg):
    """Post confirmation that an email was sent through the Nymserver to a
    non-anonymous recipient."""
    payload  = "From: send@" + NYMDOMAIN + "\n"
    payload += "To: " + msg['From'] + "\n"
    payload += "Subject: Delivery Notification for " + msg['To'] + "\n"
    payload += "Date: " + msg['Date'] + "\n"
    payload += "\n"
    payload += "Your email to " + msg['To'] + " was sent.\n"
    if 'Cc' in msg:
        payload += "It was copied to " + msg['Cc'] + "\n" 
    payload += "The Subject was: " + msg['Subject'] + "\n"
    payload += "The Message-ID was: " + msg['Message-ID'] + "\n"
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
        payload += key + ': ' + str(conf[key]) + '\n'
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

def send_no_recipient_message(email, subject):
    payload = 'Error: Message not sent\n'
    payload += underline('-', payload)
    payload += 'Your request to send a message from your nym ' + email
    payload += ' failed.\n'
    payload += 'The Subject of the message was: ' + subject + '\n'
    payload += '''
The cause of the failure is that you didn't specify any recipients in your
encrypted message.  (Whilst a Cc header will be honoured, a valid To header is
compulsory.)

The encrypted payload of your message must be formatted like a standard email
message.  It should begin with the headers, each containing a Colon-Space
between name and content.  The headers should be followed by a blank line and
then the content.

Please note, the signature on your message was successfully verified in order
to prove you were the genuine originator of the message.  A failed signature
would prevent this response to your Nym.\n'''
    return payload

def no_url_message(url):
    payload = 'Error: Could not retrieve ' + url
    return payload

def email_message(sender_email, recipient_string, message):
    """Take a sender email address and a From header-like string of
    recipients.  Split out each recipient and try to email them."""
    recipients = recipient_string.split(',')
    server = smtplib.SMTP('localhost')
    for recipient in recipients:
        name, addy = email.utils.parseaddr(recipient)
        logmessage  = 'Sending email from ' + sender_email
        logmessage += ' to ' + addy + '.'
        logging.info(logmessage)
        try:
            server.sendmail(sender_email, addy, message.as_string())
        except:
            logmessage  = 'Sending email to ' + addy
            logmessage += ' failed with error %s.' % sys.exc_info()[1]
            error_report(201, logmessage)
    server.quit()

def post_symmetric_message(payload, hash, key):
    """Symmetrically encrypt a payload and post it."""
    mid, headers  = news_headers(hash)
    logging.debug("Symmetric encrypting message with key: " + key)
    enc_payload = gnupg.symmetric(key, payload)
    nntpsend(mid, headers + '\n' + enc_payload)

def post_message(payload, conf):
    """Take a payload and add headers to it for News posting.  The dictionary
    'conf' contains specific formatting instructions."""
    mid, headers  = news_headers(conf['hsub'])
    recipient = conf['fingerprint']
    # If Symmetric encryption is specified, we don't need to throw the
    # Keyid during Asymmetric encryption.
    if conf['symmetric']:
        logging.debug('Symmetric encryption defined, not throwing KeyID')
        throwkid = False
    else:
        logging.debug('No Symmetric encryption defined, throwing KeyID')
        throwkid = True
    logging.debug('Signing and Encrypting message for ' + recipient)
    enc_payload = gnupg.signcrypt(recipient, SIGNKEY, PASSPHRASE, payload,
                                  throwkid)
    # Symmetrically wrap the payload if we have a Symmetric password defined.
    if conf['symmetric']:
        logging.debug('Adding Symmetric Encryption layer')
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
        logging.debug('Creating backup file ' + oldfile)
        copyfile(conffile, oldfile)
        logging.info('Updating user config file for ' + user)
    else:
        logging.info('Creating user config file for ' + user)
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
            logging.warn(message)
            line = key + ': False\n'
            f.write(line)
    f.close()

def user_update(confdict, text):
    """Update a user's config paramters from a text body. The current list of
    options is read from confdict and updated with those in the text.  To use
    this function, confdict must already be populated using user_read."""
    # version is locked because people send PGP keys in Modify requests and
    # the Version header in the data is treated as a config option.
    locked_keys = ['fingerprint', 'version']
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
                logging.info('Ignoring request to modify locked Key: ' + key)
            else:
                # None or False means set the key to False.
                if value.lower() == 'none' or value.lower() == 'false':
                    confdict[key] = False
                else:
                    if key in confdict:
                        logging.info('Updating ' + key + ' option.')
                    else:
                        logging.info('Creating ' + key + ' option.')
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
    """Compile a valid Message-ID."""
    leftpart = middate() + "." + midrand(12)
    mid = '<' + leftpart + '@' + rightpart + '>'
    return mid

def key_or_message(text):
    """Identify if the payload we're processing is in plain-text, a public Key
    or an encrypted message."""
    if not text:
        logging.info('Empty payload, treating as text.')
        return 'text'
    if '-----BEGIN PGP PUBLIC KEY BLOCK-----' in text \
    and '-----END PGP PUBLIC KEY BLOCK-----' in text:
        return 'key'
    if '-----BEGIN PGP MESSAGE-----' in text \
    and '-----END PGP MESSAGE-----' in text:
        return 'message'
    return 'text'

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
    logging.info('Processing received email message for: ' + xot_email)
    xot_addy, xot_domain = split_email_domain(xot_email)
    if xot_domain <> NYMDOMAIN:
        error_report(501, 'Received message for invalid domain: ' + xot_domain)
    body = msg.get_payload(decode=1)
    # Next we want to check what type of payload we're processing.
    if msg.is_multipart():
        kom = 'multipart'
    else:
        kom = key_or_message(body)

    # Start of the functionality for creating new Nyms.
    # Who was this message sent to?
    if xot_addy == 'config':
        if msg.is_multipart():
            error_report(301, 'Multipart message sent to config address.')
        # If it's a key then this can only be a new Nym request.
        if kom == 'key':
            logging.debug('Processing a new Nym request.')
            # Write any valid looking keyblock data to a tmp file.
            rc, result = key_to_file(body, TMPFILE)
            error_report(rc, result)
            # Try to import the valid looking keyblock.
            rc, fingerprint = gnupg.import_file(TMPFILE)
            error_report(rc, fingerprint)
            logging.info('Imported key ' + fingerprint)
            # If we've managed to import a key, get the email address from it.
            rc, key_email = gnupg.get_email_from_keyid(fingerprint)
            error_report(rc, key_email)
            logging.info('Extracted ' + key_email + ' from ' + fingerprint)
            # Split out the address and domain components of the email address
            key_addy, key_domain = split_email_domain(key_email)
            # Simple check to ensure the key is in the right domain.
            if key_domain <> NYMDOMAIN:
                logging.info('Deleting key ' + fingerprint)
                gnupg.delete_key(fingerprint)
                error_report(301, 'Wrong domain on ' + key_email + '.')
            # Simple check to ensure the nym isn't on the reserved list.
            if key_addy in RESERVED_NYMS:
                res_message = reserved_message(fingerprint, key_email)
                conf = {'fingerprint' : fingerprint,
                        'hsub' : False,
                        'symmetric' : False}
                post_message(res_message, conf)
                logging.info('Deleting key ' + fingerprint)
                gnupg.delete_key(fingerprint)
                error_report(301, key_addy + ' is a reserved Nym.')
            # Check if we already have a Nym with this address.
            if key_addy in nymlist:
                dup_message = duplicate_message(fingerprint, key_email)
                # We need to create a fake user config as this isn't a real
                # Nym holder.
                conf = {'fingerprint' : fingerprint,
                        'hsub' : False,
                        'symmetric' : False}
                post_message(dup_message, conf)
                logging.info('Deleting key ' + fingerprint)
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
            logging.info('Nym ' + key_addy + ' successfully created.')
            suc_message = create_success_message(key_addy)
            post_message(suc_message, conf)
        # If we've received a PGP Message to our config address, it can only
        # be a signed and encrypted request to modify a Nym config.
        elif kom == 'message':
            logmessage  = 'This email is a PGP Message. '
            logmessage += 'Assuming its a modify request.'
            logging.info(logmessage)
            rc, mod_email, content = gnupg.verify_decrypt(body, PASSPHRASE)
            error_report(rc, mod_email)
            logging.debug('Modify Nym request is for ' + mod_email + '.')
            mod_addy, mod_domain = split_email_domain(mod_email)
            # We get the user conf dictionary from user_read.
            conf = user_read(mod_addy)
            # User conf is updated by passing a plain text block of
            # key: options to user_update.
            conf = user_update(conf, content)
            # Finally we write the updated user config back to its text file.
            user_write(mod_addy, conf)
            suc_message = modify_success_message(mod_addy, conf)
            post_message(suc_message, conf)
        else:
            error_report(301, 'Not key or encrypted message.')

    # We also send messages for Nymholders after verifying their signature.
    elif xot_addy == 'send':
        # For Reference:
        # foo_from = Entire freeformat header (Foo <foo@bar.org>).
        # foo_email = Correctly formatted address (foo@bar.org).
        # foo_name = Freeform element of email address (Foo).
        # foo_addy = LHS of @ in foo_email (foo).
        # foo_domain = RHS of @ in foo_email
        if msg.is_multipart():
            error_report(301, 'Multipart message sent to send address.')
        logging.debug('Message received for forwarding.')
        rc, nym_email, content = gnupg.verify_decrypt(body, PASSPHRASE)
        error_report(rc, nym_email)
        logging.info('Verified sender is ' + nym_email)
        send_msg = email.message_from_string(content)
        # This section checks that the From header matches the verified
        # signature.  It's a matter for debate but currently it's enforced
        # as the From is set to the signature.
        if 'From' in send_msg:
            send_name, send_email = email.utils.parseaddr(send_msg['From'])
            del send_msg['From']
            send_msg['From'] = email.utils.formataddr([send_name, nym_email])
            if send_email == nym_email:
                logging.debug('From header in payload matches signature.')
            else:
                log_message  = 'From header says ' + send_email
                log_message += ' but signature is for ' + nym_email
                log_message += '. Using signature address.'
                logging.info(log_message)
        else:
            logging.info('No From header in payload, using signature.')
            send_msg['From'] = nym_email
        nym_addy, nym_domain = split_email_domain(nym_email)
        conf = user_read(nym_addy)
        if not 'Subject' in send_msg:
            logging.debug('No Subject on message, creating a dummy.')
            send_msg['Subject'] = 'No Subject'
        # Check we actually have a recipient for the message
        if 'To' not in send_msg:
            err_message = send_no_recipient_message(nym_email, send_msg['Subject'])
            post_message(err_message, conf)
            error_report(301, 'No recipient specified in To header.')
        # If we receive a Message-ID, use it, otherwise generate one.
        if 'Message-ID' in send_msg:
            logging.debug('Using provided Message-ID')
        else:
            logging.debug('Generating Message-ID for outbound message')
            send_msg['Message-ID'] = messageid(NYMDOMAIN)
        # If we receive a Date, use it, otherwise generate one.
        if 'Date' in send_msg:
            logging.debug('Using provided Date of ' + send_msg['Date'])
        else:
            send_msg['Date'] = email.utils.formatdate()
            logging.debug('Generated Date header of ' + send_msg['Date'])
        recipients = send_msg['To']
        if 'Cc' in send_msg:
            logging.debug("Cc'd to " + send_msg['Cc'])
            recipients += ',' + send_msg['Cc']
        # email message
        email_message(nym_email, recipients, send_msg)
        suc_message = send_success_message(send_msg)
        conf = user_read(nym_addy)
        logging.info('Posting Send confirmation to ' + nym_email)
        post_message(suc_message, conf)

    # Is the request for a URL retrieval?
    elif xot_addy == 'url':
        logging.debug('Received message requesting a URL.')
        # Attempt to decrypt the message
        rc, content = gnupg.decrypt(message, PASSPHRASE)
        # An rc of 200 indicates all is not well.
        if rc >= 200:
            error_report(rc, content)
        lines = content.split('\n')
        # These three variables store the required lines from within the
        # request.
        urls = []
        key = False
        hash = False
        # Parse each line of the received and decrypted message.
        for line in lines:
            if line.startswith("SOURCE "):
                url = line[7:].lstrip()
                if not url in urls:
                    urls.append(url)
                else:
                    logger.info("Duplicate request for: " + url)
            if line.startswith("KEY "):
                key = line[4:].lstrip()
            if line.startswith("HSUB "):
                hash = line[5:].lstrip()
        if len(urls) == 0:
            error_report(301, "No URL's to retrieve.")
        # We cannot proceed without a Symmetric Key.  Posting plain-text to
        # a.a.m is not a good idea.
        if not key:
            error_report(301, "No symmetric key specified.")
        if not hash:
            logging.debug("No hSub specified, setting to KEY.")
            hash = key
        # Set up the basics of our multipart MIME response.
        url_msg = MIMEMultipart('alternative')
        url_msg['From'] = 'url@' + NYMDOMAIN
        url_msg['To'] = 'somebody@alt.anonymous.messages'
        url_msg['Subject'] = 'Nym Retrieval'
        url_msg['Date'] = email.utils.formatdate()
        for url in urls:
            rc, message = urlfetch.geturl(url)
            # If there's a return code of 100 then we want to log the
            # plain-text error message, not the html content we were
            # expecting but didn't get.
            if rc >= 100:
                error_report(rc, message)
                url_part = MIMEText(message, 'plain')
            else:
                # We got a URL so attach it to the MIME message.
                logging.debug("Retreived: " + url)
                url_part = MIMEText(message, 'html')
            url_part['Content-Description'] = url
            url_msg.attach(url_part)
        # This makes the message mbox compliant so we can open it with a
        # standard mail client like Mutt.
        mime_msg = 'From foo@bar Thu Jan  1 00:00:01 1970\n'
        mime_msg += url_msg.as_string() + '\n'
        post_symmetric_message(mime_msg, hash, key)

    # If the message has got this far, it's a message to a Nym.
    else:
        if not xot_addy in nymlist:
            error_report(301, 'No public key for ' + xot_email + '.')
        logmessage  = "Processing inbound message from " + msg['From']
        logmessage += " to " + xot_addy + "."
        logging.debug(logmessage)
        if msg.is_multipart():
            logging.debug("Message is a Multipart MIME.")
        message = msg.as_string()
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
        logging.debug(desc)
    if rc >= 200 and rc < 300:
        logging.info(desc)
    if rc >= 300 and rc < 400:
        logging.info(desc + ' Aborting')
        sys.exit(rc)
    if rc >= 400 and rc < 500:
        logging.warn(desc + ' Aborting')
        sys.exit(rc)
    if rc >=500 and rc < 600:
        logging.error(desc + ' Aborting')
        sys.exit(rc)

def nntpsend(mid, content):
    payload = StringIO.StringIO(content)
    hosts = ['news.glorb.com', 'newsin.alt.net', 'localhost',
             'mixmin-in.news.arglkargh.de']
    socket.setdefaulttimeout(10)
    for host in hosts:
        logging.debug('Posting to ' + host)
        try:
            s = nntplib.NNTP(host)
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

def main():
    "Initialize logging functions, then process messages piped to stdin."
    init_logging()
    sys.stdout.write("Type message here.  Finish with Ctrl-D.\n")
    msgparse(sys.stdin.read())

# Call main function.
if (__name__ == "__main__"):
    main()
