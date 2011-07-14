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
KEYRING = os.path.join(HOMEDIR, 'keyring')
NYMDOMAIN = 'mixnym.net'
HOSTEDDOMAINS = ['is-not-my.name', 'mixnym.net']
SIGNKEY = '94F204C28BF00937EFC85D1AFF4DB66014D0C447'
HSUBLEN = 48

#gpg = gnupg.GnupgFunctions(KEYRING)
gpg = gnupg.GnupgFunctions()
gpgparse = gnupg.GnupgStatParse()

class config():
    """This is only used to store the GnuPG Passphrase after reading it from a
    file.  This is better than having it sat in a repository in plain-text."""
    def __init__(self):
        filename = os.path.join(ETCPATH, 'passphrase')
        passphrase = strutils.file2list(filename)
        if len(passphrase) == 1:
            self.passphrase = passphrase[0]
        elif len(passphrase) == 0:
            error_report(401, 'No GnuPG passphrase defined.')
        else:
            error_report(401, 'Spurious data in passphrase file.')

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

def create_success_message(userconf):
    "Respond to a successful Nym create request."
    payload  = "Congratulations!\n"
    payload += strutils.underline('-', payload)
    payload += "You have registered the pseudonym %(address)s.\n" % userconf
    payload += """
From now on, messages sent to this address will be encrypted to your key and
signed by the Nymserver before being delivered to the newsgroup
alt.anonymous.messages.

If you want to modify your Nym in the future, send a signed and encrypted
message to config@mixnym.net.  The message should contain one instruction
per line, in the format:

instruction: setting

For example, to configure an hSub password of "Panda":

hsub: Panda

Any combination of commands can be sent in the same message.  You can also
unset an option by setting it to 'none'.  E.g.
Symmetric: none

Modifications to your Nym will receive a confirmation message in
alt.anonymous.messages, formatted in accordance with your request.\n\n"""

    payload += optstring(userconf)
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

def modify_success_message(userconf):
    "Respond to successful Nym modification request."
    payload  = "Nym Modification Successful\n"
    payload += strutils.underline('-', payload)
    payload += "You have successfully modified your "
    payload += "pseudonym %(address)s.\n\n" % userconf
    payload += optstring(userconf)
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

def optstring(userconf):
    optstring = "The options currently configured on your Nym are:-\n\n"
    for key in sorted(userconf.iterkeys()):
        optstring += '%s: %s\n' % (key, userconf[key])
    return optstring

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
    enc_payload = gpg.symmetric(key, payload)
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
    enc_payload = gpg.signcrypt(recipient, SIGNKEY, config.passphrase,
                                payload, throwkid)
    # Symmetrically wrap the payload if we have a Symmetric password defined.
    if 'symmetric' in conf and conf['symmetric']:
        logging.debug('Adding Symmetric Encryption layer')
        enc_payload = gpg.symmetric(conf['symmetric'], enc_payload)
    pool_write(headers + '\n' + enc_payload)

def pool_write(payload):
    '''Write the received message (complete with headers) to the pool.
    The pool filename is formatted ayyyymmdd-rrrrrr, where r is a random lower
    case letter. The 'a' prefix indicates Anonymous and our pool processor
    will act upon it.'''
    # Create a filename for the pool file with an 'a' prefix.
    poolfile = strutils.pool_filename('a')
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
    alternatives = {'hash-subject'      :   'hsub',
                    'subject-password'  :   'hsub',
                    'hash-key'          :   'hsub'}
    ignore_fields = ['version'] # Public keys contain "Version: "
    # We ignore the next two fields to prevent warnings about MIME content.
    ignore_fields.append("content-type")
    ignore_fields.append("content-disposition")
    confopt_re = re.compile('([\w\-]+?):\s+(.+)')
    lines = text.split('\n')
    moddict = {}
    for line in lines:
        confopt = confopt_re.match(line)
        if confopt:
            # Set field to the header name and value to its content.
            field = confopt.group(1).lower()
            value = confopt.group(2).rstrip()
            # Some fields have alternative names.
            if field in alternatives:
                field = alternatives[field]
            if field in moddict:
                logging.info(field + ': Duplicate field in modify request.')
                continue
            # If we match a field:value pair, is it valid?
            if not field in valid_fields:
                if not field in ignore_fields:
                    logging.info(field + ': Invalid field in modify request.')
                continue
            # None or False means set the field to False.
            if value.lower() == 'none' or value.lower() == 'false':
                moddict[field] = False
            else:
                moddict[field] = value
    return moddict

def getuidmails(uidmails):
    """Take a list of email addresses and strip out any that aren't for our
    domains."""
    gooduids = []
    for uid in uidmails:
        foo, domain = uid.split("@", 1)
        if domain in HOSTEDDOMAINS:
            uidmails.append(uid)
    return gooduids

def split_email_domain(address):
    "Return the two parts of an email address"
    if not '@' in address:
        error_report(401, address + ': Address is not fully-qualified')
    left, right = address.split('@', 1)
    return left, right

def msgparse(message):
    "Parse a received email."
    if not options.recipient:
        logging.warn('No recipient specified. Aborting.')
        sys.exit(400)
    logging.info('Processing received email message for: ' + options.recipient)
    rname, rdomain = options.recipient.split("@", 1)
    if rdomain not in HOSTEDDOMAINS:
        logmes =  'Message is for an invalid domain: %s. Aborting.' % rdomain
        logging.warn(logmes)
        sys.exit(400)
    # specials are instances where we expect encrypted messages that we need to
    # process in some manner.
    specials = ['config', 'send', 'url']
    if rname not in specials:
        # At this point, we're assuming this is an inbound message to a Nym.
        # It might be encrypted but we don't care as we're just passing on the
        # payload to the Nym.
        nymlist = gpg.emails_to_list()
        if not options.recipient in nymlist:
            logging.info('No public key for %s.' % options.recipient)
            sys.exit(300)
        userfile = os.path.join(USERPATH, options.recipient + '.db')
        if os.path.exists(userfile):
            userconf = shelve.open(userfile)
        else:
            # This occurs when we have a recipient, with a key on the keyring
            # but no corresponding user DB.
            logging.error('%s: File not found.' % userfile)
        post_message(message, userconf)
        if 'received' in userconf:
            userconf['received'] += 1
        else:
            userconf['received'] = 1
        userconf['last_received'] = strutils.datestr()
        userconf.close()
        sys.exit(0)
        # That's it for inbound messages to Nyms.

    elif rname == 'config':
        # created is a flag that indicates if this config message is to modify
        # an existing Nym or create a new one.  In both situations we perform
        # the modification steps but the resulting success message for a create
        # needs to be different.
        created = False
        # This is where we handle processing for encrypted messages sent to
        # the config address.  This is reserved for modifications to Nyms.
        result, payload = gpg.decrypt_verify(message, config.passphrase)
        if not payload:
            # Simple bailout, we need some decrypted payload to continue.
            logging.info("No decrypted payload, probably spam")
            sys.exit(300)
        sigstat = gpgparse.statparse(result)
        if sigstat['goodsig']:
            if 'uidmail' not in sigstat:
                # No good having a signed message without an email address.
                logmes = "No email addresses on key: %(keyid)s. " % sigstat
                logmes += "Aborting."
                logging.info(logmes)
                sys.exit(300)
            # There are uids on the gpg status, we have a signed message.
            uids = getuidmails(gpgstat['uidmail'])
            if len(uids) > 1:
                # We can't handle keys with multiple emails for our domains.
                # TODO There should be a return message to the key owner.
                logmes = "%(keyid)s: Ambiguous key. " % sigstat
                logmes += "Multiple uid matches."
                logging.warn(logmes)
                sys.exit(400)
            elif len(uids) < 1:
                # We need a valid email address for the nym to receive email.
                # TODO There should be a return message to the key owner.
                logmes = "%(keyid)s: Key contains no uids for our " % sigstat
                logmes += "domains. Aborting."
                logging.warn(logmes)
                sys.exit(400)
            else:
                # This is what we require.  Just a single, valid uid for one of
                # our recognized domains.
                sigfor = uids[0] # Assign our one and only uid to sigfor.
                logmes = "Got a key with one valid UID of: %s." % sigfor
                logging.debug(logmes)
                if fingerprint not in sigstat:
                    # We should always get a fingerprint from a signed message
                    logging.error("Signed key but without fingerprint.")
                    sys.exit(500)
                else:
                    fingerprint = sigstat['fingerprint']
        else:
            # Decrypted a payload but it's unsigned. This could be a new Nym
            # request.  We have to assume so for now.
            sigfor = None
            fingerprint = None
            logmes = "Received unsigned/unknown valid GnuPG message. "
            logmes += "Assuming for now that it's a new Nym request."
            logging.info(logmes)

            # Read the keyring and put each address in a list.  This prevents
            # us from holding more than one key for any address. This has to
            # happen before we import the new key, otehrwise we can't tell if
            # the Nym existed before the import.
            nymlist = gpg.emails_to_list()

            # We import the key to test its content and then delete it later
            # if it's not acceptable.
            result = gpg.import_key(payload)
            importstat = gpgparse.statparse(result)
            # Here we check how many keys were imported. Only one is
            # considered valid.
            if importstat['imported'] == 1:
                logging.info("Imported a single key.  This is good.")
                # Put the fingerprint into a scalar for convenience
                fingerprint = importstat['fingerprint']
            elif importstat['imported'] > 1:
                logmes = "%(imported)s keys imported. " % importstat
                logmes += "We don't allow this and will now delete them."
                logging.warn(logmes)
                # TODO This is easier said than done as we don't know all the
                # imported keyids.  Need to sort this out.
                sys.exit(400)
            else:
                logging.info("No keys imported. Aborting")
                sys.exit(300)
            # By now we know a single key was imported, but how many valid
            # uids are on it?
            uids = getuidmails(importstat['uidmail'])
            if len(uids) == 1:
                sigfor = uids[0]
                logmes = "Imported KeyID %(keyid)s for " % importstat
                logmes += "email address %s." % sigfor
                logging.info(logmes)
            elif len(uids) > 1:
                logmes = "More than one valid uid on %(keyid)s. " % importstat
                logmes = "We can't allow that as each key must have a single "
                logmes = "unique identifier."
                logging.warn(logmes)
                gpg.delete_key(fingerprint)
                logmes = "Deleted key %s and aborting." % fingerprint
                logging.info(logmes)
                sys.exit(300)
            else:
                logmes = "No valid uids on imported key.  Deleting and "
                logmes += "aborting."
                gpg.delete_key(fingerprint)

            # At this stage, we have imported a valid key and verified it has
            # a single UID for one of our domains. We know the valid address
            # and have it in 'sigfor' and the fingerprint in 'fingerprint'.

            # Simple check to ensure the nym isn't on the reserved list.
            resfile = os.path.join(ETCPATH, 'reserved_nyms')
            reserved_nyms = strutils.file2list(resfile)
            nym, domain = sigfor.split("@", 1)
            if nym in reserved_nyms:
                res_message = reserved_message(fingerprint, sigfor)
                # In this instance there is no valid userconf shelve to read
                # so we create a false one to satisfy post_message().
                conf = {'fingerprint' : fingerprint}
                post_message(res_message, conf)
                logmes = "%s is a reserved Nym. Deleting key and " % nym
                logmes += "aborting."
                logging.info(logmes)
                gnupg.delete_key(fingerprint)
                sys.exit(300)
            # Check if we already hold a key matching the address on this
            # create request.  If we do, send a duplicate request and then
            # delete this key.
            if sigfor in nymlist:
                logmsg = "%s: Requested but already exists. " % sigfor
                logmsg += "Sending duplicate Nym message, then deleting the "
                logmes += "key and aborting."
                logging.info(logmsg)
                dup_message = duplicate_message(fingerprint, sigfor)
                # Create a false userconf as this isn't a valid user.
                conf = {'fingerprint' : fingerprint}
                post_message(dup_message, conf)
                gnupg.delete_key(fingerprint)
                sys.exit(300)

            # If script execution gets here, we know we're dealing with an
            # accepted new Nym.
            userfile = os.path.join(USERPATH, sigfor + '.db')
            # This is a creation process, the user file can't already exist.
            if os.path.exists(userfile):
                # This should never happen.  We can't have an accepted new Nym
                # with an existing DB file.
                logging.error("%s: File already exists." % userfile)
            logging.info('Creating user config file %s' % userfile)
            userconf = shelve.open(userfile)
            userconf['fingerprint'] = fingerprint
            userconf['created'] = strutils.datestr()
            userconf['address'] = sigfor
            # Write the public key to a file, just in case we ever need it.
            filename = os.path.join(USERPATH, sigfor + '.key')
            f = open(filename, 'w')
            f.write(gpg.export(fingerprint) + '\n') 
            created = True  # Flag this as a newly created Nym
            logmes = "%s: Nym was successfully created" % sigfor

        # We're past the new Nym phase.  Everything from here is common to all
        # messages sent to config@foo.
        logging.debug('%s: Entering config modify routine.' % sigfor)
        if not created:
            # If we haven't done a create, the userconf isn't open yet.
            userfile = os.path.join(USERPATH, sigfor + '.db')
            # This is a modify process, the user file must already exist.
            if os.path.isfile(userfile):
                userconf = shelve.open(userfile)
            else:
                # In theory this can't happen.  We can't be modifying a Nym
                # that doesn't already have a config file.
                logging.error("%s: File doesn't exist." % userconf)
                sys.exit(500)
        # user_update creates a new dict of keys that need to be created or
        # changed in the master userconf dict.
        moddict = user_update(payload)
        # Does the mod request include a Delete statement?
        if 'delete' in moddict and moddict['delete'].lower() == 'yes':
            logmessage  = sigfor + ": Starting delete process "
            logmessage += "at user request."
            logging.info(logmessage)
            delete_nym(sigfor, userconf)
            logging.info("%s: Nym has been deleted." % sigfor)
            sys.exit(300)
        modified = False
        for key in moddict:
            # The following condition only dictates which logmessage to
            # write.  The dictionary is updated regardless.
            if key in userconf:
                logmes  = 'Changing key %s from %s' % (key, userconf[key])
                logmes += ' to %s.' % moddict[key]
                logging.debug(logmes)
            else:
                logmes  = 'Inserting key %s' % key
                logmes += ' with value %s.' % moddict[key]
                logging.debug(logmes)
            userconf[key] = moddict[key]
            modified = True
        if modified and not created:
            # Add (or update) the modified date in the user configuration
            userconf['modified'] = strutils.datestr()
        elif not modified and not created:
            logging.info("%s: Nothing modified. Sending status." % sigfor)
        # Everyone should have their address in the user configuration
        if not 'address' in userconf:
            logging.debug("Adding address to userconf.")
            userconf['address'] = sigfor
        if created:
            reply_message = create_success_message(userconf)
        else:
            reply_message = modify_success_message(userconf)
            logging.debug("Created modify reply message")
        post_message(reply_message, userconf)
        userconf.close()

    # We also send messages for Nymholders after verifying their signature.
    elif rname == "send":
        if sigfor is None:
            # Reject the message if we can't verify the sender.
            error_report(301, "Unsigned message to send@")
        # For Reference:
        # foo_from = Entire freeformat header (Foo <foo@bar.org>).
        # foo_email = Correctly formatted address (foo@bar.org).
        # foo_name = Freeform element of email address (Foo).
        # foo_addy = LHS of @ in foo_email (foo).
        # foo_domain = RHS of @ in foo_email
        logging.debug('Message received for forwarding.')
        logging.info('Verified sender is ' + sigfor)
        send_msg = email.message_from_string(payload)
        # This section checks that the From header matches the verified
        # signature.  It's a matter for debate but currently it's enforced
        # as the From is set to the signature.
        if 'From' in send_msg:
            send_name, send_email = email.utils.parseaddr(send_msg['From'])
            del send_msg['From']
            send_msg['From'] = email.utils.formataddr([send_name, sigfor])
            if send_email == sigfor:
                logging.debug('From header in payload matches signature.')
            else:
                log_message  = 'From header says ' + send_email
                log_message += ' but signature is for ' + sigfor
                log_message += '. Using signature address.'
                logging.info(log_message)
        else:
            logging.info('No From header in payload, using signature.')
            send_msg['From'] = sigfor
        userfile = os.path.join(USERPATH, sigfor + '.db')
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
            err_message = send_no_recipient_message(sigfor, send_msg['Subject'])
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
        email_message(sigfor, recipients, send_msg)
        suc_message = send_success_message(send_msg)
        logging.info('Posting Send confirmation to ' + sigfor)
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
        logmes =  '%s has sent %d' % (sigfor, userconf['sent_today'])
        logmes += ' messages today and %d in total.' % userconf['sent']
        logging.debug(logmes)
        if userconf['sent_today'] > 50:
            userconf['block_sends'] = True
            logmes =  '%s has exceeded daily sending allowance.' % sigfor
            logmes += ' Sending is now disabled until manual intervention'
            logmes += ' re-enables it.'
            logging.warn(logmes)
        userconf.close()

    # Is the request for a URL retrieval?
    elif rname == 'url':
        logging.debug('Received message requesting a URL.')
        # An rc of 200 indicates all is not well.
        lines = payload.split('\n')
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
    # 300   Exit, Info message
    # 400   Abort, Warn message
    # 500   Abort, Error message
    if rc >= 100 and rc < 200:
        logging.debug(desc)
    if rc >= 200 and rc < 300:
        logging.info(desc)
    if rc >= 300 and rc < 400:
        logging.info(desc + ' Exiting')
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
    rc, nymlist = gnupg.emails_to_list()
    for nym in nymlist:
        addy, domain = split_email_domain(nym)
        if addy in reserved_nyms:
            continue
        userfile = os.path.join(USERPATH, nym + '.db')
        keyfile = os.path.join(USERPATH, nym + '.key')
        if os.path.exists(userfile):
            userconf = shelve.open(userfile)
            if not 'address' in userconf:
                userconf['address'] = nym
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
    global config
    config = config()
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

