#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 noautoindent
#
# nymserv.py - A Basic Nymserver for delivering messages to a shared mailbox
# such as alt.anonymous.messages.
#
# Copyright (C) 2011 Steve Crook <steve@mixmin.net>
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

from email.parser import Parser
from strutils import file2list
from time import sleep
import cStringIO
import email
import email.utils
import logging
import mailbox as mbx
import nntplib
import os
import os.path
import re
import shelve
import smtplib
import socket
import sys
# My libraries
from daemon import Daemon
import gnupg
import hsub
import strutils
import URL_Handler
from Config import options
from Config import config

class MyDaemon(Daemon):
    def run(self):
        while True:
            mailbox.process()
            pool.process()
            sleep(3600)

class PoolPost:
    def __init__(self, etcpath, poolpath):
        socket.setdefaulttimeout(10)
        hostfile = os.path.join(etcpath, 'newsservers')
        if not os.path.isfile(hostfile):
            logging.error('%s: Peers file does not exist' % hostfile)
            sys.exit(1)
        self.hosts = file2list(hostfile)
        if len(self.hosts) == 0:
            logging.error('No news peers defined.')
            sys.exit(1)
        self.poolpath = poolpath

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
            except socket.gaierror, e:
                logging.warn('%s: Connection error: %s' % (host, e))
            except:
                logging.warn('Untrapped error during connect to %s' % host)
        return peers

    def process(self):
        """Produce a list of files in the pool and perform some basic checks
        on the configured Usenet peers.  If all is good, pass the list of
        files to the post_files routine.

        """
        pool_files = self.listdir(self.poolpath)
        # If the pool has no files in it, we don't need to do anything.
        num_pool_files = len(pool_files)
        if num_pool_files == 0:
            logging.info('No files in pool to process so no action required.')
        else:
            logging.info('Processing %s pool files' % num_pool_files)
            peers = self.connect_peers()
            # If there are no host connections, log it and give up.
            if len(peers) == 0:
                logmes  = 'All %s peer connections' % len(self.hosts)
                logmes += ' failed. Check Internet connection, it might be dead.'
                logging.warn(logmes)
            else:
                self.post_files(peers, pool_files)

    def post_files(self, peers, pool_files):
        """Attempt tp post a list of files handed to us by process().

        """
        # Iterate through all the files in the pool
        for filename in pool_files:
             # Bool set to true if any newsserver accepts the post
            success = False
            # Create a fully-qualified filename to avoid any confusion
            fqname = os.path.join(self.poolpath, filename)
            f = open(fqname, 'r')

            # We need to parse the message headers to find out what the
            # Message-ID is.  Also, in some cases we need to rewrite headers
            # for anonymity purposes.
            msg = Parser().parse(f, 'headersonly')
            f.close()
            # For anonymity purposes, we want to create dates at injection
            # time, not at creation time.  Otherwise there's no point in
            # batching delivery.
            if filename.startswith('a'):
                # Lowercase 'a' means anonymous and we need to massage some
                # headers to prevent giving away clues.
                logging.debug('Adjusting linkable headers')
                d = email.utils.formatdate()
                if 'Date' in msg:
                    logging.debug('Deleting Date header: %s' % msg['Date'])
                    del msg['Date']
                logging.debug('Inserting Date header: %s' % d)
                msg['Date'] = d
                if 'Injection-Date' in msg:
                    logmes = 'Deleting Injection-Date header:'
                    logmes += ' %s' % msg['Injection-Date']
                    logging.debug(logmes)
                    del msg['Injection-Date']
                logging.debug('Inserting Injection-Date header: %s' % d)
                msg['Injection-Date'] = d
            # Here we extract the Message-ID so we can offer it to our news
            # peers during IHAVE.
            if 'Message-ID' in msg:
                mid = msg['Message-ID']
                logging.debug('%s: Contains Message-ID: %s' % (filename, mid))
            else:
                logmes = '%s: Contains no Message-ID. Skipping.' % filename
                logging.warn(logmes)
                continue

            o = cStringIO.StringIO()
            logging.debug('Attempting to post %s.' % filename)
            o.write(msg.as_string())
            # Now we offer the message to our peers and hope at least one
            # accepts.
            for host in peers:
                o.seek(0) # Start from the beginning of our file
                try:
                    peers[host].ihave(mid, o)
                    success = True
                    logging.debug('%s: Accepted %s' % (host, mid))
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
            o.close()

            # Check the success flag.  If True we can delete the file from the
            # pool.  If not, log it.
            if success:
                os.remove(fqname)
                logging.info('%s: Posted and deleted from pool' % filename)
            else:
                logging.warn('%s: Not accepted. Retaining in pool' % filename)

        # Finally close the connections to our peers.
        for host in peers:
            try:
                peers[host].quit()
                logging.debug('%s: Connection Closed' % host)
            except socket.error, e:
                logmes = '%s: Cannot close connection. ' % host
                logmes += 'Socket Error: %s' % e
                logging.warn(logmes)
        # Processing completed normally.

class Mailbox():
    def process(self):
        """Parse a Maildir and pass each identified message to the Nymserver
        for processing.  Failed messages will be stored in a held queue.

        """
        # The inbox is where we expect to read messages from.
        inbox = mbx.Maildir(config.get('paths', 'maildir'))
        # After reading from inbox, failed messages are written to held.
        held = mbx.Maildir(config.get('paths', 'held'))
        logging.info("Beginning mailbox processing")
        allcnt = 0 # Total messags parsed
        goodcnt = 0 # Successfully processed count
        badcnt = 0 # Failed and held count
        for key in inbox.iterkeys():
            message = inbox.get_string(key)
            recipient = self.ascertain_recipient(message)
            allcnt += 1
            if recipient is None:
                processed = False
                badcnt += 1
            else:
                processed = msgparse(recipient, message)
            if processed:
                    goodcnt += 1
            else:
                heldkey = held.add(message)
                logmes = "Message processing failed.  Saving as %s" % heldkey
                logging.warn(logmes)
            # We discard the message from inbox, regardless of whether it was
            # successfully processed, otherwise we'll keep retrying it.
            inbox.discard(key)
            logging.debug("Deleted %s from mailq" % key)
        logmes = "Mailbox processing completed. "
        logmes += "%s of %s successful." % (goodcnt, allcnt)
        if badcnt > 0:
            logmes += " %s failed and held." % badcnt
        logging.info(logmes)

    def ascertain_recipient(self, message):
        """This function attempts to work out who the recipient of a message
        is.  Not as easy as it sounds!  Postfix appends an X-Original-To
        header containing this info but there's no guarantee of its uniqueness
        as other systems (such as mailing lists) also append the same header.
        Consequently it's necessary to parse the whole header in search of an
        X-Original-To matching the domains the Nymserver processes.

        """
        doms = config.get('domains', 'hosted')
        msglines = message.split("\n")
        for line in msglines:
            if not line.startswith("X-Original-To: "):
                continue
            # Strip the header from its content.
            recipient = line.split(": ", 1)[1]
            # Hopefully the content is an email address.
            if not '@' in recipient:
                logging.info("Invalid recipient found: %s" % recipient)
                continue
            # Split the email address and validate the domain.
            domain = recipient.split("@", 1)[1]
            if domain in doms:
                logging.info("Extracted valid recipient: %s" % recipient)
                return recipient
            else:
                logging.info("Unwanted recipient: %s" % recipient)
                continue
            # When we encounter an empty line, it's the end of the header section.
            if not line:
                logmes = "We got a message with no ascertainable recipient "
                logmes += "for the Nymserver. This probably shouldn't happen."
                logging.warn(logmes)
                return None
        logmes = "Unable to ascertain a recipient for this message. "
        logmes += "End of message was reached without finding a recipient "
        logmes += "or a blank line after the headers."
        logging.warn(logmes)
        return None

class UpdateUser():
    def __init__(self):
        # Valid fields are those that are deemed user-definable.
        self.valid_fields = ['symmetric', 'hsub', 'delete', 'subject']
        self.alternatives = {'hash-subject'      :   'hsub',
                             'subject-password'  :   'hsub',
                             'hash-key'          :   'hsub'}
        ignore_fields = ['version'] # Public keys contain "Version: "
        # We ignore the next two fields to prevent warnings about MIME content.
        ignore_fields.append("content-type")
        ignore_fields.append("content-disposition")
        self.confopt_re = re.compile('([\w\-]+?):\s*(.+)')
        self.ignore_fields = ignore_fields
    
    def make_moddict(self, text):
        """Parse a block of text for lines in the format Key: Option.  Compare
        these with a list of valid fields and then construct a dictionary of
        these options for return.

        """
        lines = text.split('\n')
        moddict = {}
        for line in lines:
            confopt = self.confopt_re.match(line)
            if not confopt:
                continue
            # Set field to the header name and value to its content.
            field = confopt.group(1).lower()
            value = confopt.group(2).rstrip()
            # Some fields have alternative names.
            if field in self.alternatives:
                field = self.alternatives[field]
            if field in moddict:
                logmes = "%s: Duplicate field in modify request." % field
                logging.info(logmes)
                continue
            # If we match a field:value pair, is it valid?
            if not field in self.valid_fields:
                if not field in self.ignore_fields:
                    logmes = "%s: Invalid field in modify " % field
                    logmes += "request"
                    logging.info(logmes)
                continue
            # None or False means set the field to False.
            if value.lower() == 'none' or value.lower() == 'false':
                moddict[field] = False
            else:
                moddict[field] = value
        return moddict

class PostPrep():
    def __init__(self):
        self.hsub = hsub.HSub(config.getint('hsub', 'length'))

    def news_headers(self, conf):
        """For all messages inbound to a.a.m for a Nym, the headers are
        standard.  The only required info is whether to hSub the Subject. We
        expect to be passed an hsub value if this is required, otherwise a
        fake is used.

        """
        # A full hex hSub is 80 hex digits. It's trimmed to match the length of
        # other systems, such as eSub.
        mid = strutils.messageid(config.get('domains', 'default'))
        message  = "Path: %s\n" % config.get('nntp', 'path')
        message += "From: %s\n" % config.get('nntp', 'from')
        if 'hsub' in conf and conf['hsub']:
            # We use an hsub if we've been passed one.
            logging.debug("Generating hSub using key: " + conf['hsub'])
            hash = self.hsub.hash(conf['hsub'])
            message += "Subject: " + hash + '\n'
            logging.info("Generated a real hSub: " + hash)
        elif 'subject' in conf and conf['subject']:
            # We're doing a plain-text Subject.
            message += "Subject: %s\n" % conf['subject']
            logging.info("Using plain-text subject: %s" % conf['subject'])
        else:
            # We're doing a fake hsub.
            # We have to half the hsublen because we want the return in Hex
            # where each byte takes 2 digits.  To be safe, fetch too much
            # entropy and then trim it to size.
            hsublen = config.getint('hsub', 'length')
            randbytes = int(hsublen / 2 + 1)
            hash = self.hsub.cryptorandom(randbytes).encode('hex')
            hash = hash[:hsublen]
            message += "Subject: " + hash + "\n"
            logging.info("Fake hSub: " + hash)
        message += "Date: " + email.utils.formatdate() + "\n"
        message += "Message-ID: " + mid + "\n"
        message += "Newsgroups: %s\n" % config.get('nntp', 'newsgroups')
        message += "Injection-Info: %s; " % config.get('nntp', 'injectinfo')
        message += "mail-complaints-to=\"%s\"\n" % \
                                            config.get('nntp', 'contact')
        message += "Injection-Date: " + email.utils.formatdate() + "\n"
        return mid, message

    def post_symmetric_message(self, payload, hash, key):
        """Symmetrically encrypt a payload and post it.  This function is
        currently only called for posting URLs.

        """
        # We need our hsub hash in a dictionary because that's what
        # news_headers expects to receive.
        dummy_conf = { "hsub" : hash }
        mid, headers  = self.news_headers(dummy_conf)
        logging.debug("Symmetric encrypting message with key: " + key)
        enc_payload = gpg.symmetric(key, payload)
        logging.debug("Writing symmetric message to pool.")
        self.pool_write(headers + '\n' + enc_payload)

    def post_message(self, payload, conf):
        """Take a payload and add headers to it for News posting.  The
        dictionary 'conf' contains specific formatting instructions.

        """
        mid, headers  = self.news_headers(conf)
        if not 'fingerprint' in conf:
            conf.close()
            logging.error('User shelve contains no fingerprint key.')
            return False
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
        result, enc_payload = gpg.signcrypt(recipient,
                                    config.get('pgp', 'key'),
                                    config.get('pgp', 'passphrase'),
                                    payload,
                                    throwkid)
        if enc_payload:
            # Symmetrically wrap the payload if we have a Symmetric password
            # defined.
            if 'symmetric' in conf and conf['symmetric']:
                logging.debug('Adding Symmetric Encryption layer')
                enc_payload = gpg.symmetric(conf['symmetric'], enc_payload)
            self.pool_write(headers + '\n' + enc_payload)
        elif result:
            logmes = "GnuPG returned an error whilst attempting to signcrypt "
            logmes += "a message.  The error was:\n%s" % result
            logging.error(logmes)
        else:
            logmes = "GnuPG returned no payload or error during signcrypt. "
            logmes += "The recipient was: %s" % recipient
            logging.error(logmes)

    def pool_write(self, payload):
        """Write the received message (complete with headers) to the pool.  The
        pool filename is formatted ayyyymmdd-rrrrrr, where r is a random lower
        case letter. The 'a' prefix indicates Anonymous and our pool processor
        will act upon it.

        """
        # Create a filename for the pool file with an 'a' prefix.
        poolfile = strutils.pool_filename('a')
        fq_poolfile = os.path.join(config.get('paths', 'pool'), poolfile)
        # Write the pool file
        f = open(fq_poolfile, 'w')
        f.write(payload)
        logging.info('%s: Added to pool' % poolfile)
        f.close()



def init_logging():
    loglevels = {'debug': logging.DEBUG, 'info': logging.INFO,
                'warn': logging.WARN, 'error': logging.ERROR}
    logging.basicConfig(
        filename=os.path.join(config.get('paths', 'logdir'), 'nym.log'),
        level = loglevels[config.get('logging', 'level')],
        format = '%(asctime)s %(process)d %(levelname)s %(message)s',
        datefmt = '%Y-%m-%d %H:%M:%S')

def send_success_message(msg):
    """Post confirmation that an email was sent through the Nymserver to a
    non-anonymous recipient."""
    payload  = "From: send@" + config.get('domains', 'default') + "\n"
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

def duplicate_message(keyid, addy):
    payload  = "Error - Duplicate Nym Address " + addy + ".\n"
    payload += strutils.underline('-', payload)
    payload += """
You attempted to register a Nym that already exists on the server.  You are
receiving this response because the server can send a message encrypted to
the unique key you created but external users can only send to an email
address.  Hence, the email address must be unique.\n"""
    payload += "\nThe key " + keyid + " "
    payload += "will now be deleted from the server.\n"
    return payload

def reserved_message(keyid, addy):
    payload  = 'Error - ' + addy + " is a reserved Nym.\n"
    payload += strutils.underline('-', payload)
    payload += """
You attempted to register a reserved Nym name.  You are receiving this response
because the server can send a message encrypted to the unique key you created
but the Nym will not be functional.\n"""
    payload += "\nThe key " + keyid + " "
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
            logging.info(logmessage)
    server.quit()

def getuidmails(uidmails):
    """Take a list of email addresses and strip out any that aren't for our
    domains."""
    gooduids = []
    # We fetch the domain list as a comma seperated string from config.
    # str2list then converts it to a list of hosted domains.
    doms = config.get('domains', 'hosted')
    for uid in uidmails:
        foo, domain = uid.split("@", 1)
        if domain in doms:
            gooduids.append(uid)
    return gooduids

def msgparse(recipient, message):
    "Parse a received email."
    # Split a recipient email address into two components; local-part and
    # domain.
    rlocal, rdomain = recipient.split('@', 1)
    # require_pgp is a list of recipients for whom we expect encrypted messages
    # that require processing in some manner.
    require_pgp = ['config', 'send', 'url']
    if rlocal not in require_pgp:
        # At this point, we're assuming this is an inbound message to a Nym.
        # It might be encrypted but we don't care as we're just passing on the
        # payload to the Nym.
        nymlist = gpg.emails_to_list()
        if not recipient in nymlist:
            logging.info('Unknown recipient %s.' % recipient)
            return True
        userfile = os.path.join(config.get('paths', 'user'),
                                recipient + '.db')
        if os.path.exists(userfile):
            userconf = shelve.open(userfile)
        else:
            # This occurs when we have a recipient, with a key on the keyring
            # but no corresponding user DB.
            logging.warn('%s: File not found.' % userfile)
            return False
        postprep.post_message(message, userconf)
        if 'received' in userconf:
            userconf['received'] += 1
        else:
            userconf['received'] = 1
        userconf['last_received'] = strutils.datestr()
        userconf.close()
        return True
        # That's it for inbound messages to Nyms.

    # The recipient requires pgp processing. Let's start by trying to
    # decrypt and verify the message.
    result, payload = gpg.decrypt_verify(message,
                                         config.get('pgp', 'passphrase'))
    if not payload:
        # Simple bailout, we need some decrypted payload to continue.
        logmes = "No decrypted payload, probably spam. "
        logmes += "Result was:\n%s" % result
        logging.info(logmes)
        processed = True
    elif rlocal == 'config':
        processed = process_config(result, payload)
    elif rlocal == "send":
        processed = process_send(result, payload)
    elif rlocal == 'url':
        processed = process_url(payload)
    return processed

def process_config(result, payload):
    sigstat = gpgparse.statparse(result)
    if 'goodsig' in sigstat and sigstat['goodsig']:
        # At this point, we cannot be dealing with a create message. We
        # know the key in order to have verified the signature.

        # created is a flag that indicates if this config message is to
        # modify an existing Nym or create a new one.  In both situations
        # we perform the modification steps but the resulting success
        # message for a create needs to be different.
        created = False

        if 'uidmail' not in sigstat:
            # No good having a signed message without an email address.
            logmes = "No email addresses on key: %(keyid)s." % sigstat
            logging.warn(logmes)
            return False
        # We pass the last check so there are email uid's on the signature.
        # Let's now check if any of them are for our domains.
        uids = getuidmails(sigstat['uidmail'])
        if len(uids) > 1:
            # We can't handle keys with multiple emails for our domains.
            # TODO There should be a return message to the key owner.
            logmes = "%(keyid)s: Ambiguous key. " % sigstat
            logmes += "Multiple uid matches."
            logging.warn(logmes)
            return False
        elif len(uids) < 1:
            # We need a valid email address for the nym to receive email.
            # TODO There should be a return message to the key owner.
            logmes = "%(keyid)s: Key contains no uids for our " % sigstat
            logmes += "domains."
            logging.warn(logmes)
            return False
        else:
            # This is what we require.  Just a single, valid uid for one of
            # our recognized domains.
            sigfor = uids[0] # Assign our one and only uid to sigfor.
            logmes = "Got a key with one valid UID of: %s." % sigfor
            logging.debug(logmes)
            if 'fingerprint' in sigstat:
                fingerprint = sigstat['fingerprint']
            else:
                # We should always get a fingerprint from a signed message
                logmes = "%(keyid)s Signed key but without " % sigstat
                logmes += "fingerprint. Status reported was:\n"
                logmes += result
                logging.error(logmes)
                return False
    else:
        # Decrypted a payload but it's unsigned. This could be a new Nym
        # request.  We have to assume so for now.
        logmes = "Received unsigned/unknown valid GnuPG message. "
        logmes += "Assuming for now that it's a new Nym request."
        logging.info(logmes)

        # Read the keyring and put each address in a list.  This prevents
        # us from holding more than one key for any address. This has to
        # happen before we import the new key, otehrwise we can't tell if
        # the Nym existed before the import.
        nymlist = gpg.emails_to_list()

        # We import the key to obtain its secrets, like keyid and uids.
        # By setting dryrun=True, the key isn't imported to our
        # real keyring. That will happen later if it passes scrutiny.
        result = gpg.import_key(payload, dryrun = True)
        testimpstat = gpgparse.statparse(result)
        # Here we check how many keys were imported. Only one is
        # considered valid.
        if 'imported' not in testimpstat:
            logging.error("No 'imported' returned by importstat.")
            return False
        elif testimpstat['imported'] > 1:
            logmes = "%(imported)s keys imported. " % testimpstat
            logmes += "We don't allow more than one."
            logging.warn(logmes)
            return False
        elif testimpstat['imported'] == 1 and 'keyid' in testimpstat:
            logmes = "Imported key %(keyid)s has a single UID. " % testimpstat
            logmes += "Excellent! Proceeding with import process."
            logging.info(logmes)
        else:
            logmes = "We got an unanticipated return from an attempted key "
            logmes += "import.  The GnuPG status was:\n%s" % result
            logging.error(logmes)
            return False
        # By now we know a single key was imported, but how many valid
        # uids are on it?
        uids = getuidmails(testimpstat['uidmail'])
        if len(uids) == 1:
            sigfor = uids[0]
            logmes = "Test imported KeyID %(keyid)s for " % testimpstat
            logmes += "email address %s." % sigfor
            logging.info(logmes)
        elif len(uids) > 1:
            logmes = "More than one valid uid on %(keyid)s. " % testimpstat
            logmes = "We can't allow that as each key must have a single "
            logmes = "unique identifier."
            logging.warn(logmes)
            return False
        else:
            # We didn't get any valid uids.
            logging.warn("No valid uids on test imported key.")
            #TODO The return on this should be True but for now, False will
            #     cause the message to be held for human validation.
            return False

        # At this stage, we have imported a valid key on to a fake keyring and
        # verified it has a single UID for one of our domains. We know the
        # valid address and have it in 'sigfor'. We'd like the fingerprint too
        # but that's tricky as we've only test imported the key.  Now we will
        # import it for real, even though we may yet reject it.  Having it on
        # the real keyring means we can encrypt response messages to the
        # sender.
        logging.info("Importing %s. This time for real." % sigfor)
        result = gpg.import_key(payload)
        logging.debug("Import result was:\n%s" % result)
        importstat = gpgparse.statparse(result)
        logging.debug("Imported Keyid: %s" % importstat['keyid'])
        if 'fingerprint' in importstat:
            fingerprint = importstat['fingerprint']
        else:
            logmes = "Fingerprint not obtained during import. Requesting "
            logmes += "it now."
            logging.debug(logmes)
            fingerprint = gpg.fingerprint(importstat['keyid'])
            if fingerprint is None:
                logmes = "Failed to obtain fingerprint for "
                logmes += "%(keyid)s" % importstat
                logging.error(logmes)
                return False
        logging.debug("Imported fingerprint is %s." % fingerprint)

        # Simple check to ensure the nym isn't on the reserved list.
        resfile = os.path.join(config.get('paths', 'etc'), 'reserved_nyms')
        reserved_nyms = strutils.file2list(resfile)
        nym, domain = sigfor.split("@", 1)
        if nym in reserved_nyms:
            res_message = reserved_message(importstat['keyid'], sigfor)
            # In this instance there is no valid userconf shelve to read so we
            # create a false one to satisfy post_message().
            conf = {'fingerprint' : fingerprint}
            postprep.post_message(res_message, conf)
            gnupg.delete_key(fingerprint)
            logging.info("%s is a reserved Nym. Deleted key." % nym)
            return True

        userfile = os.path.join(config.get('paths', 'user'),
                                sigfor + '.db')
        if os.path.isfile(userfile):
            logmes = "%s: This nym already has a DB file. " % sigfor
            logmes += "It could be a duplicate, or a key update. Checking it."
            logging.info(logmes)
            userconf = shelve.open(userfile)
            fp = userconf['fingerprint']
            userconf.close()
            if fp == fingerprint:
                logmes = "%s: Fingerprints match, it's a key " % sigfor
                logmes += "refresh.  We've already imported it, so no "
                logmes += "further action is required."
                logging.info(logmes)
                return True
            else:
                logging.info("It's a duplicate, not accepting it.")
                dup_message = duplicate_message(importstat['keyid'], sigfor)
                # Create a false userconf as this isn't a valid user.
                conf = {'fingerprint' : fingerprint}
                postprep.post_message(dup_message, conf)
                gpg.delete_key(fingerprint)
                logmes = "%s: Requested but already exists. " % sigfor
                logmes += "Sent duplicate Nym message and deleted key."
                logging.info(logmes)
                return True

        # If script execution gets here, we know we're dealing with an
        # accepted new Nym.

        # This is a creation process, the user file can't already exist.
        if os.path.isfile(userfile):
            # This should never happen.  We can't have an accepted new Nym
            # with an existing DB file.
            logging.error("%s: File already exists." % userfile)
            return False
        logging.info('Creating user config file %s' % userfile)
        userconf = shelve.open(userfile)
        userconf['fingerprint'] = fingerprint
        userconf['created'] = strutils.datestr()
        userconf['address'] = sigfor
        # Write the public key to a file, just in case we ever need it.
        filename = os.path.join(config.get('paths', 'user'),
                                sigfor + '.key')
        f = open(filename, 'w')
        f.write(gpg.export(fingerprint) + '\n') 
        f.close()
        os.chmod(filename, 0600)

        created = True  # Flag this as a newly created Nym
        logmes = "%s: Nym was successfully created" % sigfor

    # We're past the new Nym phase.  Everything from here is common to all
    # messages sent to config@foo.
    logging.debug('%s: Entering config modify routine.' % sigfor)
    if not created:
        # If we haven't done a create, the userconf isn't open yet.
        userfile = os.path.join(config.get('paths', 'user'),
                                sigfor + '.db')
        # This is a modify process, the user file must already exist.
        if os.path.isfile(userfile):
            userconf = shelve.open(userfile)
        else:
            # In theory this can't happen.  We can't be modifying a Nym that
            # doesn't already have a config file.
            logging.error("%s: File doesn't exist." % userconf)
            return False
    # user_update creates a new dict of keys that need to be created or changed
    # in the master userconf dict.
    moddict = updusr.make_moddict(payload)
    # Does the mod request include a Delete statement?
    if 'delete' in moddict and moddict['delete'].lower() == 'yes':
        logmessage  = sigfor + ": Starting delete process "
        logmessage += "at user request."
        logging.info(logmessage)
        delete_nym(sigfor, userconf)
        logging.info("%s: Nym has been deleted." % sigfor)
        return True
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
        logging.debug("Created newnym reply message")
    else:
        reply_message = modify_success_message(userconf)
        logging.debug("Created modify reply message")
    postprep.post_message(reply_message, userconf)
    userconf.close()
    return True

def process_send(result, payload):
    logging.debug('Message received for forwarding.')
    # We send messages for Nymholders after verifying their signature.
    sigstat = gpgparse.statparse(result)
    if 'goodsig' not in sigstat or not sigstat['goodsig']:
        logging.info("Only verified signatures can send messages.")
        return True
    if 'uidmail' not in sigstat:
        # No good having a signed message without an email address.
        logmes = "We verified a signature, meaning we accepted is once, but "
        logmes += "it has no valid email uids for our domains. This requires "
        logmes += "some manual investigation. GnuPG status was:-\n"
        logmes += "%s\n" % result
        logging.error(logmes)
        return False
    # There are uids on the gpg status, we have a signed message.
    uids = getuidmails(sigstat['uidmail'])
    if len(uids) > 1:
        # We can't handle keys with multiple emails for our domains.
        logmes = "Well this shouldn't happen! During nym creation we "
        logmes += "validated this key with only a single valid uid. Now it "
        logmes += "has %s.  GnuPG status was:-\n" % len(uids)
        logmes += "%s\n" % result
        logging.error(logmes)
        return False
    elif len(uids) < 1:
        # We need a valid email address for the nym to receive email.
        logmes = "Well this shouldn't happen! During nym creation we "
        logmes += "validated this key with a valid uid. Now it "
        logmes += "doesn't have one.  GnuPG status was:-\n"
        logmes += "%s\n" % result
        logging.error(logmes)
        return False
    else:
        # This is what we require.  Just a single, valid uid for one of
        # our recognized domains.
        sigfor = uids[0] # Assign our one and only uid to sigfor.
        logmes = "Got a key with one valid UID of: %s." % sigfor
        logging.debug(logmes)
        if 'fingerprint' not in sigstat:
            # We should always get a fingerprint from a signed message
            logmes = "%(keyid)s Signed key but without " % sigstat
            logmes += "fingerprint. Status reported was:\n"
            logmes += "%s\n" % result
            logging.error(logmes)
            return False
        else:
            fingerprint = sigstat['fingerprint']

    # For Reference:
    # foo_from = Entire freeformat header (Foo <foo@bar.org>).
    # foo_email = Correctly formatted address (foo@bar.org).
    # foo_name = Freeform element of email address (Foo).
    # foo_addy = LHS of @ in foo_email (foo).
    # foo_domain = RHS of @ in foo_email
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
            logmes = "From header says %s " % send_email
            logmes += "but signature is for %s. " % sigfor
            logmes += "Using signature address."
            logging.info(logmes)
    else:
        logging.info('No From header in payload, using signature.')
        send_msg['From'] = sigfor
    userfile = os.path.join(config.get('paths', 'user'),
                            sigfor + '.db')
    if os.path.exists(userfile):
        userconf = shelve.open(userfile)
    else:
        logging.error(userfile + ': File not found.')
        return False
    # Reject sending if block_sends is defined and true
    if 'block_sends' in userconf and userconf['block_sends']:
        logging.info(nym_email + ': Sending email is blocked')
        #TODO Change this return to True after (if ever) it's proven.
        return False
    if not 'Subject' in send_msg:
        logging.debug('No Subject on message, creating a dummy.')
        send_msg['Subject'] = 'No Subject'
    # Check we actually have a recipient for the message
    if 'To' not in send_msg:
        err_message = send_no_recipient_message(sigfor, send_msg['Subject'])
        postprep.post_message(err_message, userconf)
        userconf.close()
        logging.info('No recipient specified in To header.')
        return True
    # If we receive a Message-ID, use it, otherwise generate one.
    if 'Message-ID' in send_msg:
        logging.debug('Using provided Message-ID')
    else:
        send_mid = strutils.messageid(config.get('domains', 'default'))
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
    postprep.post_message(suc_message, userconf)
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
    if userconf['sent_today'] > config.getint('thresholds',
                                              'daily_send_limit'):
        userconf['block_sends'] = True
        logmes =  '%s has exceeded daily sending allowance.' % sigfor
        logmes += ' Sending is now disabled until manual intervention'
        logmes += ' re-enables it.'
        logging.warn(logmes)
    userconf.close()
    return True

def process_url(payload):
    logging.debug('Received message requesting a URL.')
    try:
        urls, key, hsubhash = urlhandler.extract_directives(payload)
    except URL_Handler.DirectiveError, e:
        # Malformed URL request, log and delete as there's not much else we
        # can do abou it.
        logging.info(e)
        return True 
    mime_msg = urlhandler.fetch_and_prep(urls)
    postprep.post_symmetric_message(mime_msg, hsubhash, key)
    return True

def delete_nym(email, userconf):
    # First we make an in-memory copy of the user conf as we're about to delete
    # the files and shelves for it.
    memcopy = {}
    for key in userconf:
        memcopy[key] = userconf[key]
    # We now have an in-memory copy so we can close the shelve and delete it.
    userconf.close()
    from os import remove
    keyfile = os.path.join(config.get('paths', 'user'), email + '.key')
    userfile = os.path.join(config.get('paths', 'user'), email + '.db')
    if os.path.exists(userfile):
        logging.info('Deleting userfile: ' + userfile)
        remove(userfile)
    if os.path.exists(keyfile):
        logging.info('Deleting keyfile: ' + keyfile)
        remove(keyfile)
    # We have to post the delete message before we remove the key from the
    # keyring, otherwise we can't encrypt the message!
    del_message = delete_success_message(email)
    postprep.post_message(del_message, memcopy)
    logging.info('%(fingerprint)s: Deleting from keyring.' % memcopy)
    gpg.delete_key(memcopy['fingerprint'])
    logging.info('Deletion process complete.')
    return True

def stdout_user(user):
    """Respond to a --list <email> request with a list of configuration
    options for the given user."""
    userfile = os.path.join(config.get('paths', 'user'), user + '.db')
    if not os.path.exists(userfile):
        sys.stdout.write(userfile + ': File not found\n')
        sys.exit(1)
    userconf = shelve.open(userfile)
    today = strutils.datestr()
    if 'last_sent' in userconf and userconf['last_sent'] <> today:
        userconf['sent_today'] = 0
    for key in userconf:
        sys.stdout.write('%s: %s\n' % (key, userconf[key]))
    userconf.close()
    sys.exit(0)

def delete(email):
    from os import remove
    keyfile = os.path.join(config.get('paths', 'user'), email + '.key')
    userfile = os.path.join(config.get('paths', 'user'), email + '.db')
    if os.path.exists(userfile):
        sys.stdout.write('Deleting userfile: %s\n' % userfile)
        remove(userfile)
    if os.path.exists(keyfile):
        logging.info('Deleting keyfile: %s\n' % keyfile)
        remove(keyfile)
    sys.stdout.write("Deleting key: %s\n" % email)
    fp = gpg.fingerprint(email)
    sys.stdout.write("Fingerprint for %s is %s\n" % (email, fp))
    if fp is not None:
        gpg.delete_key(fp)
        sys.stdout.write("%s: Deleted" % fp)
        sys.exit(0)
    logmes = "%s: Key not deleted, unable to determine Fingerprint.\n" % fp
    sys.stdout.write(logmes)
    sys.exit(1)

def cleanup():
    resfile = os.path.join(config.get('paths', 'etc'), 'reserved_nyms')
    reserved_nyms = strutils.file2list(resfile)
    rc, nymlist = gpg.emails_to_list()
    for nym in nymlist:
        addy, domain = nym.split("@", 1)
        if addy in reserved_nyms:
            continue
        userfile = os.path.join(config.get('paths', 'user'), nym + '.db')
        keyfile = os.path.join(config.get('paths', 'user'), nym + '.key')
        if os.path.exists(userfile):
            userconf = shelve.open(userfile)
            if not 'address' in userconf:
                userconf['address'] = nym
            if not os.path.isfile(keyfile):
                f = open(keyfile, 'w')
                f.write(gpg.export(userconf['fingerprint']) + '\n') 
                f.close()
            userconf.close()
            sys.stdout.write(nym + "\n")
    sys.exit(0)    

def main():
    if options.cleanup:
        cleanup()
    elif options.list:
        stdout_user(options.list)
    elif options.delete:
        delete(options.delete)
    elif options.recipient:
        sys.stdout.write("Type message here.  Finish with Ctrl-D.\n")
        logging.info("Processing message for hardcoded recipient %s" % \
                     options.recipient)
        msgparse(options.recipient, sys.stdin.read())
    elif options.process:
        mailbox.process()
        pool.process()
    elif options.start:
        logging.info("Daemon starting")
        daemon.start()
    elif options.stop:
        logging.info("Daemon stopping")
        daemon.stop()
    elif options.restart:
        logging.info("Daemon restarting")
        daemon.restart()
    else:
        sys.stdout.write("No command specified\n")

# Call main function.
if (__name__ == "__main__"):
    init_logging()
    # Initialize the Daemon
    daemon = MyDaemon(
            os.path.join(config.get('paths', 'piddir'), 'nymserv.pid'),
            '/dev/null',
            '/dev/null',
            os.path.join(config.get('paths', 'logdir'), 'error')
            )
    updusr = UpdateUser()
    pool = PoolPost(config.get('paths', 'etc'),
                    config.get('paths', 'pool')
                   )
    postprep = PostPrep()
    gpg = gnupg.GnuPGFunctions(config.get('pgp', 'keyring'))
    gpgparse = gnupg.GnuPGStatParse()
    urlhandler = URL_Handler.URL()
    mailbox = Mailbox()
    main()

