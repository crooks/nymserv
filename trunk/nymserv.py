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
import sys
import shelve
import smtplib
import cStringIO
import email.utils
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.application import MIMEApplication
from optparse import OptionParser
# My libraries
import gnupg
import hsub
import urlfetch
import strutils

LOGLEVEL = 'debug'
HOMEDIR = os.path.expanduser('~')
LOGPATH = os.path.join(HOMEDIR, 'log')
USERPATH = os.path.join(HOMEDIR, 'users')
ETCPATH = os.path.join(HOMEDIR, 'etc')
POOLPATH = os.path.join(HOMEDIR, 'pool')
NYMDOMAIN = 'is-not-my.name'
HOSTEDDOMAINS = ['is-not-my.name', 'mixnym.net']
SIGNKEY = '94F204C28BF00937EFC85D1AFF4DB66014D0C447'
PASSPHRASE = '3VnAyesMXmJEVSlXJMq2'
HSUBLEN = 48

def init_logging():
    loglevels = {'debug': logging.DEBUG, 'info': logging.INFO,
                'warn': logging.WARN, 'error': logging.ERROR}
    logfile = os.path.join(LOGPATH, strutils.datestr())
    logging.basicConfig(
        filename=logfile,
        level = loglevels[LOGLEVEL],
        format = '%(asctime)s %(process)d %(levelname)s %(message)s',
        datefmt = '%Y-%m-%d %H:%M:%S')

def init_parser():
    "Parse command line options."
    parser = OptionParser()

    parser.add_option("-r", "--recipient", dest = "recipient",
                      help = "Recipient email address")
    parser.add_option("-l", "--list", dest = "list",
                      help = "List user configuration")
    parser.add_option("--cleanup", dest = "cleanup", action = "store_true",
                      default=False, help = "Perform some housekeeping")
    return parser.parse_args()

def news_headers(conf):
    """For all messages inbound to a.a.m for a Nym, the headers are standard.
    The only required info is whether to hSub the Subject.  We expect to be
    passed an hsub value if this is required, otherwise a fake is used."""
    mid = strutils.messageid(NYMDOMAIN)
    message  = "Path: nymserv.mixmin.net!not-for-mail\n"
    message += "From: Anonymous <nobody@mixmin.net>\n"
    if 'hsub' in conf and conf['hsub']:
        # We use an hsub if we've been passed one.
        logging.debug("Generating hSub using key: " + conf['hsub'])
        hash = hsub.hash(conf['hsub'], HSUBLEN)
        message += "Subject: " + hash + '\n'
        logging.debug("Generated a real hSub: " + hash)
    elif 'subject' in conf and conf['subject']:
        # We're doing a plain-text Subject.
        message += "Subject: %s\n" % conf['subject']
        logging.debug("Using plain-text subject: %s" % conf['subject'])
    else:
        # We're doing a fake hsub.
        # We have to half the HSUBLEN because we want the return in Hex
        # where each byte takes 2 digits.  To be safe, fetch too much entropy
        # and then trim it to size.
        randbytes = int(HSUBLEN / 2 + 1)
        hash = hsub.cryptorandom(randbytes).encode('hex')
        hash = hash[:HSUBLEN]
        message += "Subject: " + hash + "\n"
        logging.debug("Fake hSub: " + hash)
    message += "Date: " + email.utils.formatdate() + "\n"
    message += "Message-ID: " + mid + "\n"
    message += "Newsgroups: alt.anonymous.messages\n"
    message += "Injection-Info: nymserv.mixmin.net; "
    message += "mail-complaints-to=\"abuse@mixmin.net\"\n"
    message += "Injection-Date: " + email.utils.formatdate() + "\n"
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

def create_success_message(email):
    "Respond to a successful Nym create request."
    payload  = "Congratulations!\n"
    payload += strutils.underline('-', payload)
    payload += "You have registered the pseudonym " + email + ".\n"
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

def delete_success_message(email):
    "Respond to a successful Nym delete request."
    payload  = "Nym Deletion in progress!\n"
    payload += strutils.underline('-', payload)
    payload += "Your nym " + email + " is now being deleted.\n"
    payload += """
As per your modification request, your nym is now being deleted from the
server.  This is the last message the server will be able to encrypt to this
key.  As part of the deletion process, the Nym configuration will also be
deleted.  Should you decide to recreate the Nym, it will begin with a default
configuration.  Good-Bye, it's been good!\n"""
    return payload

def modify_success_message(email, userconf):
    "Respond to successful Nym modification request."
    payload  = "Nym Modification Successful\n"
    payload += strutils.underline('-', payload)
    payload += "You have successfully modified you pseudonym " + email + ".\n\n"
    payload += "After modification, the options configured on your nym are:-\n"
    useropts = ['fingerprint', 'symmetric', 'hsub']
    for key in useropts:
        if key in userconf:
            payload += '%s: %s\n' % (key, userconf[key])
    return payload

def duplicate_message(fingerprint, addy):
    payload  = "Error - Duplicate Nym Address " + addy + ".\n"
    payload += strutils.underline('-', payload)
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
    payload += strutils.underline('-', payload)
    payload += """
You attempted to register a reserved Nym name.  You are receiving this response
because the server can send a message encrypted to the unique key you created
but the Nym will not be functional.\n"""
    payload += "\nThe key " + fingerprint + " "
    payload += "will now be deleted from the server.\n"
    return payload

def send_no_recipient_message(email, subject):
    payload = 'Error: Message not sent\n'
    payload += strutils.underline('-', payload)
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
    """Take a sender email address and a To header-like string of
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
    """Symmetrically encrypt a payload and post it.  This function is
    currently only called for posting URLs"""
    # We need our hsub hash in a dictionary because that's what news_headers
    # expects to receive.
    dummy_conf = { "hsub" : hash }
    mid, headers  = news_headers(dummy_conf)
    logging.debug("Symmetric encrypting message with key: " + key)
    enc_payload = gnupg.symmetric(key, payload)
    logging.debug("Passing message to NNTP Send")
    pool_write(headers + '\n' + enc_payload)

def post_message(payload, conf):
    """Take a payload and add headers to it for News posting.  The dictionary
    'conf' contains specific formatting instructions."""
    mid, headers  = news_headers(conf)
    if not 'fingerprint' in conf:
        conf.close()
        error_report(501, 'User shelve contains no fingerprint key.')
    recipient = conf['fingerprint']
    # If Symmetric encryption is specified, we don't need to throw the
    # Keyid during Asymmetric encryption.
    if 'symmetric' in conf and conf['symmetric']:
        logging.debug('Symmetric encryption defined, not throwing KeyID')
        throwkid = False
    else:
        logging.debug('No Symmetric encryption defined, throwing KeyID')
        throwkid = True
    logging.debug('Signing and Encrypting message for ' + recipient)
    enc_payload = gnupg.signcrypt(recipient, SIGNKEY, PASSPHRASE, payload,
                                  throwkid)
    # Symmetrically wrap the payload if we have a Symmetric password defined.
    if 'symmetric' in conf and conf['symmetric']:
        logging.debug('Adding Symmetric Encryption layer')
        enc_payload = gnupg.symmetric(conf['symmetric'], enc_payload)
    pool_write(headers + '\n' + enc_payload)

def pool_write(payload):
    '''Write the received message (complete with headers) to the pool.
    The pool filename is formatted yyyymmdd-rrrrrr, where r is a random lower
    case letter.'''
    # Create a filename for the pool file
    poolfile = strutils.pool_filename()
    fq_poolfile = os.path.join(POOLPATH, poolfile)
    # Write the pool file
    f = open(fq_poolfile, 'w')
    f.write(payload)
    logging.info('%s: Added to pool' % poolfile)
    f.close()

def user_update(text):
    """Parse a block of text for lines in the format Key: Option.
    Compare these with a list of valid fields and then construct a dictionary
    of these options for return."""
    # Valid fields are those that are deemed user-definable.
    valid_fields = ['symmetric', 'hsub', 'delete', 'subject']
    confopt_re = re.compile('(\w+?):\s+(.+)')
    lines = text.split('\n')
    moddict = {}
    for line in lines:
        confopt = confopt_re.match(line)
        if confopt:
            # Set field to the header name and value to its content.
            field = confopt.group(1).lower()
            value = confopt.group(2).rstrip()
            if field in moddict:
                logging.info(field + ': Duplicate field in modify request.')
                continue
            # If we match a field:value pair, is it valid?
            if not field in valid_fields:
                logging.info(field + ': Invalid field in modify request.')
                continue
            # None or False means set the field to False.
            if value.lower() == 'none' or value.lower() == 'false':
                moddict[field] = False
            else:
                moddict[field] = value
    return moddict

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

def split_email_domain(address):
    "Return the two parts of an email address"
    if not '@' in address:
        error_report(401, address + ': Address is not fully-qualified')
    left, right = address.split('@', 1)
    return left, right

def msgparse(message):
    "Parse a received email."
    if not options.recipient:
        error_report(501, 'No recipient specified.')
    logging.info('Processing received email message for: ' + options.recipient)
    recipient_addy, recipient_domain = split_email_domain(options.recipient)
    if recipient_domain not in HOSTEDDOMAINS:
        logmessage =  'Message is for an invalid domain: '
        logmessage += recipient_domain
        error_report(501, logmessage)

    # nymlist will contain a list of all the nyms currently on the server
    rc, nymlist = gnupg.emails_to_list()

    # Use the email library to create the msg object.
    msg = email.message_from_string(message)
    body = msg.get_payload(decode=1)
    # Next we want to check what type of payload we're processing.
    if msg.is_multipart():
        kom = 'multipart'
    else:
        kom = key_or_message(body)

    # Start of the functionality for creating new Nyms.
    # Who was this message sent to?
    if options.recipient.startswith('config@'):
        if msg.is_multipart():
            error_report(301, 'Multipart message sent to config address.')
        # If it's a key then this can only be a new Nym request.
        if kom == 'key':
            logging.info('This is a new Nym request.')
            # Try to import the potential keyblock.
            rc, fingerprint = gnupg.import_key(body)
            error_report(rc, fingerprint)
            logging.info('Imported key ' + fingerprint)
            # If we've managed to import a key, get the email address from it.
            rc, key_email = gnupg.get_email_from_keyid(fingerprint)
            error_report(rc, key_email)
            logging.info('Extracted ' + key_email + ' from ' + fingerprint)
            # Split out the address and domain components of the email address
            key_addy, key_domain = split_email_domain(key_email)
            # Simple check to ensure the key is in the right domain.
            if key_domain not in HOSTEDDOMAINS:
                logging.info('Deleting key ' + fingerprint)
                gnupg.delete_key(fingerprint)
                error_report(301, 'Invalid domain on ' + key_email + '.')
            # Simple check to ensure the nym isn't on the reserved list.
            resfile = os.path.join(ETCPATH, 'reserved_nyms')
            reserved_nyms = strutils.file2list(resfile)
            if key_addy in reserved_nyms:
                res_message = reserved_message(fingerprint, key_email)
                # In this instance there is no valid userconf shelve to read
                # so we create a false one to satisfy post_message().
                conf = {'fingerprint' : fingerprint}
                post_message(res_message, conf)
                logging.info('Deleting key ' + fingerprint)
                gnupg.delete_key(fingerprint)
                error_report(301, key_addy + ' is a reserved Nym.')
            # Check if we already have a Nym with this address.
            if key_email in nymlist:
                dup_message = duplicate_message(fingerprint, key_email)
                # Create a false userconf as this isn't a valid user.
                conf = {'fingerprint' : fingerprint}
                post_message(dup_message, conf)
                logging.info('Deleting key ' + fingerprint)
                gnupg.delete_key(fingerprint)
                error_report(301, 'Nym ' + key_addy + ' already exists.')
            # If script execution gets here, we know we're dealing with an
            # accepted new Nym.
            userfile = os.path.join(USERPATH, key_email + '.db')
            # This is a creation process, the user file can't already exist.
            if os.path.exists(userfile):
                error_report(501, userfile + ': File already exists.')
            logging.info('Creating ' + userfile)
            userconf = shelve.open(userfile)
            userconf['fingerprint'] = fingerprint
            userconf['created'] = strutils.datestr()
            # Write the public key to a file, just in case we ever need it.
            filename = os.path.join(USERPATH, key_email + '.key')
            f = open(filename, 'w')
            f.write(gnupg.export(fingerprint) + '\n') 
            f.close()
            logging.info('Nym ' + key_email + ' successfully created.')
            suc_message = create_success_message(key_email)
            post_message(suc_message, userconf)
            userconf.close()
        # If we've received a PGP Message to our config address, it can only
        # be a signed and encrypted request to modify a Nym config.
        elif kom == 'message':
            logmessage  = 'This email is a PGP Message. '
            logmessage += 'Assuming its a modify request.'
            logging.info(logmessage)
            rc, mod_email, content = gnupg.verify_decrypt(body, PASSPHRASE)
            error_report(rc, mod_email)
            logging.debug('Modify Nym request is for ' + mod_email + '.')
            userfile = os.path.join(USERPATH, mod_email + '.db')
            if os.path.exists(userfile):
                userconf = shelve.open(userfile)
            else:
                error_report(501, userfile + ': File not found.')
            # user_update creates a new dict of keys that need to be created or
            # changed in the master userconf dict.
            moddict = user_update(content)
            # Does the mod request include a Delete statement?
            if 'delete' in moddict and moddict['delete'].lower() == 'yes':
                logmessage  = mod_email + ": Starting delete process "
                logmessage += "at user request."
                logging.info(logmessage)
                delete_nym(mod_email, userconf)
                error_report(301, mod_email + " has been deleted.")
            for key in moddict:
                if key in userconf:
                    logmes  = 'Changing key %s from %s' % (key, userconf[key])
                    logmes += ' to %s.' % moddict[key]
                    logging.debug(logmes)
                else:
                    logmes  = 'Inserting key %s' % key
                    logmes += ' with value %s.' % moddict[key]
                    logging.debug(logmes)
                userconf[key] = moddict[key]
            # Add (or update) the modified date and then close the shelve.
            userconf['modified'] = strutils.datestr()
            suc_message = modify_success_message(mod_email, userconf)
            post_message(suc_message, userconf)
            userconf.close()
        else:
            error_report(301, 'Not key or encrypted message.')

    # We also send messages for Nymholders after verifying their signature.
    elif options.recipient.startswith('send@'):
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
        userfile = os.path.join(USERPATH, nym_email + '.db')
        if os.path.exists(userfile):
            userconf = shelve.open(userfile)
        else:
            error_report(501, userfile + ': File not found.')
	# Reject sending if block_sends is defined and true
	if 'block_sends' in userconf and userconf['block_sends']:
		error_report(301, nym_email + ': Sending email is blocked')
        if not 'Subject' in send_msg:
            logging.debug('No Subject on message, creating a dummy.')
            send_msg['Subject'] = 'No Subject'
        # Check we actually have a recipient for the message
        if 'To' not in send_msg:
            err_message = send_no_recipient_message(nym_email, send_msg['Subject'])
            post_message(err_message, userconf)
            userconf.close()
            error_report(301, 'No recipient specified in To header.')
        # If we receive a Message-ID, use it, otherwise generate one.
        if 'Message-ID' in send_msg:
            logging.debug('Using provided Message-ID')
        else:
            send_mid = strutils.messageid(NYMDOMAIN)
            logmes  = 'Generating Message-ID ' + send_mid
            logmes += ' for outbound message.'
            logging.info(logmes)
            send_msg['Message-ID'] = send_mid
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
        logging.info('Posting Send confirmation to ' + nym_email)
        post_message(suc_message, userconf)
        if 'sent' in userconf:
            userconf['sent'] += 1
        else:
            userconf['sent'] = 1
        # Get today's date as a string
        today = strutils.datestr()
        if not 'last_sent' in userconf:
            # We've never sent a message, we have now!
            userconf['last_sent'] = today
        elif userconf['last_sent'] <> today:
            # If the last time we sent a message wasn't today, sent_today needs
            # resetting.
            logging.debug('Resetting Sent Today count to zero')
            userconf['sent_today'] = 0
        # Now we set last_sent to today, regardless of any conditions.
        userconf['last_sent'] = today
        if 'sent_today' in userconf:
            userconf['sent_today'] += 1
        else:
            userconf['sent_today'] = 1
        logmes =  '%s has sent %d' % (nym_email, userconf['sent_today'])
        logmes += ' messages today and %d in total.' % userconf['sent']
        logging.debug(logmes)
        if userconf['sent_today'] > 50:
            userconf['block_sends'] = True
            logmes =  '%s has exceeded daily sending allowance.' % nym_email
            logmes += ' Sending is now disabled until manual intervention'
            logmes += ' re-enables it.'
            logging.warn(logmes)
        userconf.close()

    # Is the request for a URL retrieval?
    elif options.recipient.startswith('url@'):
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
                    logging.info("Duplicate request for: " + url)
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
        handled_mime_types = ['text', 'application', 'image']
        for url in urls:
            # ct is Content-Type header.
            rc, message, ct = urlfetch.geturl(url)
            # All MIME Types consist of a Type and a Sub-Type
            # If there's a return code of 100 then we want to log the
            # plain-text error message, not the html content we were
            # expecting but didn't get.
            if rc >= 100:
                error_report(rc, message)
                url_part = MIMEText(message, 'plain')
                url_part['Content-Description'] = url
                url_msg.attach(url_part)
                continue

            # OK, we have retrieved a URL of some type.  Now to figure our
            # exactly what it is.
            logging.info("Retrieved: " + url + "  Type: " + ct)

            # If we don't know the Content-Type, we can't encode it.
            if not ct:
                error_message = "Cannot verify Content-Type for " + url
                logging.warn(error_message)
                url_part = MIMEText(error_message, 'plain')
                url_part['Content-Description'] = url
                url_msg.attach(url_part)
                continue

            # If we get here then we must have a Content-Type
            if '/' in ct:
                type, slashright = ct.split('/')
                # The Content-Type can include the Charset.  This is always
                # delimited with a semi-colon.
                elements = slashright.split(';')
                # First bit after the slash is always the subtype.
                subtype = elements.pop(0)
                charset = False
                for element in elements:
                    clean_element = element.strip()
                    if clean_element.startswith('charset='):
                        charset = clean_element.split('=')[1]
                        logging.debug('Charset defined as: ' + charset)
                        break

            else:
                error_message = "Content-Type " + ct + "has no / in it"
                logging.warn(error_message)
                url_part = MIMEText(error_message, 'plain')
                url_part['Content-Description'] = url
                url_msg.attach(url_part)
                continue

            # We have a URL and know what type it is.
            if not type in handled_mime_types:
                error_message = "Cannot handle " + type + "files"
                logging.warn(error_message)
                url_part = MIMEText(error_message, 'plain')
            elif type == 'image':
                # We got a URL and it appears to be an image.
                url_part = MIMEImage(message, subtype)
            elif type == 'application':
                # We got a URL and it appears to be a binary app.
                url_part = MIMEApplication(message, subtype)
            elif type == 'text':
                if charset:
                    url_part = MIMEText(message, subtype, charset)
                else:
                    url_part = MIMEText(message, subtype)
            url_part['Content-Description'] = url
            url_msg.attach(url_part)

        # This makes the message mbox compliant so we can open it with a
        # standard mail client like Mutt.
        mime_msg = 'From foo@bar Thu Jan  1 00:00:01 1970\n'
        mime_msg += url_msg.as_string() + '\n'
        post_symmetric_message(mime_msg, hash, key)

    # If the message has got this far, it's a message to a Nym.
    else:
        if not options.recipient in nymlist:
            error_report(301, 'No public key for ' + options.recipient + '.')
        logmessage  = "Message is inbound from " + msg['From']
        logmessage += " to " + options.recipient + "."
        logging.info(logmessage)
        if msg.is_multipart():
            logging.debug("Message is a Multipart MIME.")
        message = msg.as_string()
        userfile = os.path.join(USERPATH, options.recipient + '.db')
        if os.path.exists(userfile):
            userconf = shelve.open(userfile)
        else:
            error_report(501, userfile + ': File not found.')
        post_message(message, userconf)
        if 'received' in userconf:
            userconf['received'] += 1
        else:
            userconf['received'] = 1
        userconf['last_received'] = strutils.datestr()
        userconf.close()

def delete_nym(email, userconf):
    # First we make an in-memory copy of the user conf as we're about to delete
    # the files and shelves for it.
    memcopy = {}
    for key in userconf:
        memcopy[key] = userconf[key]
    # We now have an in-memory copy so we can close the shelve and delete it.
    userconf.close()
    from os import remove
    keyfile = os.path.join(USERPATH, email + '.key')
    userfile = os.path.join(USERPATH, email + '.db')
    if os.path.exists(userfile):
        logging.info('Deleting userfile: ' + userfile)
        remove(userfile)
    if os.path.exists(keyfile):
        logging.info('Deleting keyfile: ' + keyfile)
        remove(keyfile)
    # We have to post the delete message before we remove the key from the
    # keyring, otherwise we can't encrypt the message!
    del_message = delete_success_message(email)
    post_message(del_message, memcopy)
    logging.info(memcopy['fingerprint'] + ': Deleting from keyring.')
    gnupg.delete_key(memcopy['fingerprint'])
    logging.info('Deletion process complete.  Exiting.')
    sys.exit(0)

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

def stdout_user(user):
    """Respond to a --list <email> request with a list of configuration
    options for the given user."""
    userfile = os.path.join(USERPATH, user + '.db')
    if not os.path.exists(userfile):
        sys.stdout.write(userfile + ': File not found\n')
        sys.exit(1)
    userconf = shelve.open(userfile)
    for key in userconf:
        sys.stdout.write('%s: %s\n' % (key, userconf[key]))
    userconf.close()
    sys.exit(0)

def cleanup():
    resfile = os.path.join(ETCPATH, 'reserved_nyms')
    reserved_nyms = strutils.file2list(resfile)
    valid_keys = ['fingerprint', 'created', 'hsub', 'sent', 'last_sent',
                  'symmetric', 'modified', 'received', 'last_received']
    rc, nymlist = gnupg.emails_to_list()
    for nym in nymlist:
        addy, domain = split_email_domain(nym)
        if addy in reserved_nyms:
            continue
        userfile = os.path.join(USERPATH, nym + '.db')
        if os.path.exists(userfile):
            userconf = shelve.open(userfile)
            if not 'created' in userconf:
                userconf['created'] = strutils.datestr()
            for key in userconf:
                if not key in valid_keys:
                    del userconf[key]
            # Write the public key to a file, just in case we ever need it.
            keyfile = os.path.join(USERPATH, nym + '.key')
            if not os.path.isfile(keyfile):
                f = open(keyfile, 'w')
                f.write(gnupg.export(userconf['fingerprint']) + '\n') 
                f.close()
            userconf.close()
            sys.stdout.write(nym + "\n")
    sys.exit(0)    

def main():
    "Initialize logging functions, then process messages piped to stdin."
    init_logging()
    global options
    (options, args) = init_parser()
    global hsub 
    hsub = hsub.HSub()
    if options.cleanup:
        cleanup()
    if options.list:
        stdout_user(options.list)
    if options.recipient:
        sys.stdout.write("Type message here.  Finish with Ctrl-D.\n")
        msgparse(sys.stdin.read())
    else:
        sys.stdout.write("Error: No recipient specified.\n")

# Call main function.
if (__name__ == "__main__"):
    main()
