#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 autoindent
#
# gnupg.py - GnuPG functionality through GnuPGInterface.
# $Id$
#
# Copyright (C) 2010 Steve Crook <steve@mixmin.net>
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

from GnuPGInterface import GnuPG
import re
import tempfile
import os.path
import email.utils
import time

HOMEDIR = os.path.expanduser('~')
#KEYRING = os.path.join(HOMEDIR, 'keyring')
KEYRING = os.path.join(HOMEDIR, '.gnupg')

class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class GnupgError(Error):
    """GnuPG Verification Errors"""
    def __init__(self, expr):
        self.expr = expr
    def __str__(self):
        return repr(self.expr)

class gpgFunctions(GnuPG):
    def decrypt_verify(self, message, passphrase):
        """This function is unusual in that it returns 3 variables:
        Return Code, Result (Email if verified), Decrypted Payload."""
        self.options.armor = 1
        self.options.meta_interactive = 0
        self.options.always_trust = 1
        self.options.homedir = KEYRING
        self.passphrase = passphrase
        proc = self.run(['--decrypt'], create_fhs=['stdin',
                                                   'stdout',
                                                   'logger'])
        proc.handles['stdin'].write(message)
        proc.handles['stdin'].close()
        result = proc.handles['logger'].read()
        content = proc.handles['stdout'].read()
        proc.handles['logger'].close()
        proc.handles['stdout'].close()
        return result, content

    def export(self, keyid):
        self.options.armor = 1
        self.options.meta_interactive = 0
        self.options.homedir = KEYRING
        idlist = []
        idlist.append(keyid)
        proc = self.run(['--export'], args=idlist, create_fhs=['stdout',
                                                               'logger'])
        result = proc.handles['logger'].read()
        key = proc.handles['stdout'].read()
        proc.handles['stdout'].close()
        proc.wait()
        # result isn't returned as it doesn't mean much from an export.
        return key

    def keyinfo(self, keyid):
        self.options.armor = 1
        self.options.meta_interactive = 0
        self.options.homedir = KEYRING
        idlist = []
        idlist.append(keyid)
        proc = self.run(['--list-keys'], args=idlist, create_fhs=['stdout'])
        result = proc.handles['stdout'].read()
        proc.handles['stdout'].close()
        proc.wait()
        return result

def emails_to_list():
    gnupg.options.armor = 1
    gnupg.options.meta_interactive = 0
    gnupg.options.homedir = KEYRING
    proc = gnupg.run(['--list-keys'], create_fhs=['stdout'])
    result = proc.handles['stdout'].read()
    proc.handles['stdout'].close()
    proc.wait()
    lines = result.split('\n')
    addresses = []
    for line in lines:
        is_email = re.search(email_re, line)
        if is_email:
            addresses.append(is_email.group(0))
    return 001, addresses

def fingerprint(email):
    """Return the fingerprint of a given email address. If we can't get the
    fingerprint, we return False."""
    gnupg.options.meta_interactive = 0
    gnupg.options.homedir = KEYRING
    idlist = []
    idlist.append(email)
    proc = gnupg.run(['--fingerprint'], args=idlist, create_fhs=['stdout'])
    key = proc.handles['stdout'].read()
    proc.handles['stdout'].close()
    finger_re = re.search( \
            'Key fingerprint = ([0-9A-F\s]+)', key)
    if finger_re:
        finger = finger_re.group(1)
        finger_list = finger.split()
        finger = ''.join(finger_list)
        return finger
    else:
        return False

def delete_key(keyid):
    gnupg.options.meta_interactive = 0
    gnupg.options.homedir = KEYRING
    idlist = []
    idlist.append(keyid)
    proc = gnupg.run(['--delete-key'], args=idlist)
    #proc.handles['stderr'].close()

def import_key(key):
    """Import a PGP key and if successful, return its Fingerprint"""
    keyfile = tempfile.NamedTemporaryFile()
    keyfile.write(key)
    keyfile.seek(0)
    filelist = []
    filelist.append(keyfile.name)
    gnupg.options.meta_interactive = 0
    gnupg.options.homedir = KEYRING
    proc = gnupg.run(['--import'], args=filelist, create_fhs=['logger'])
    result = proc.handles['logger'].read()
    proc.handles['logger'].close()
    keyfile.close()
    for line in result.split("\n"):
        # GnuPG status lines begin with "gpg: "
        if line.startswith("gpg: "):
            if "no valid OpenPGP data found" in line:
                return 301, "No PGP key found during attempted import."
    # We only ever want to work on a single key so we return False if we're
    # trying to process more than one.
    # TODO By the time we realise we've got more than one, we've already
    #      imported them all.  This isn't ideal.
    number_processed_re = re.search(r'Total number processed: (\d+)', result)
    if not number_processed_re:
        return 501, 'GnuPG failed to return processed key count.'
    number_processed = int(number_processed_re.group(1))
    if number_processed <> 1:
        return 301, 'Keyblock contains more or less than a single key.'
    # Next, if we've not actually imported the key, return False.
    # TODO ----- UNREMARK THE FOLLOWING FOR LIVE -----
    imported_re = re.search(r'imported: (\d+)', result)
    if not imported_re:
        return 301, 'GnuPG reports no imported keys.'
    imported = int(imported_re.group(1))
    if imported <> 1:
        return 301, 'Imported more or less than a single key.'

    # If all has gone well, we should now be able to extract the keyid from
    # the import result and obtain its Fingerprint to return.
    keyid_re = re.search(r'key ([0-9A-F]{8}):', result)
    if not keyid_re:
        return 501, 'No KeyID identified during import.'
    keyid = keyid_re.group(1)
    finger = fingerprint(keyid)
    if not finger:
        return 501, 'Failed to obtain fingerprint from imported key.'
    # Return the fingerprint of the imported key
    return 001, finger

def verify(message):
    gnupg.options.armor = 1
    gnupg.options.meta_interactive = 0
    gnupg.options.always_trust = 1
    gnupg.options.homedir = KEYRING
    proc = gnupg.run(['--verify'], create_fhs=['stdin', 'logger'])
    proc.handles['stdin'].write(message)
    proc.handles['stdin'].close()
    result = proc.handles['logger'].read()
    proc.handles['logger'].close()
    return result
    addys = []
    goodsig = False
    lines = result.split('\n')
    for line in lines:
        print line
        if not line.startswith('gpg: '):
            continue
        gpgmsg = line.lstrip('gpg: ')
        if gpgmsg.startswith('Good signature'):
            goodsig = True
        address = email_re.search(line)
        if address:
            addys.append(address.group(0))
        if (gpgmsg.startswith("Can't check signature") or
            gpgmsg.startswith("no signature found") or
            gpgmsg.startswith("BAD signature")):
            raise VerifyError(gpgmsg)
    if not goodsig:
        raise VerifyError("No identifiable signature")
    return addys

def vdtest(message, passphrase):
    """This function is unusual in that it returns 3 variables:
    Return Code, Result (Email if verified), Decrypted Payload."""
    gnupg.options.armor = 1
    gnupg.options.meta_interactive = 0
    gnupg.options.always_trust = 1
    gnupg.options.homedir = KEYRING
    gnupg.passphrase = passphrase
    proc = gnupg.run(['--decrypt'], create_fhs=['stdin', 'stdout', 'logger'])
    proc.handles['stdin'].write(message)
    proc.handles['stdin'].close()
    result = proc.handles['logger'].read()
    content = proc.handles['stdout'].read()
    proc.handles['logger'].close()
    proc.handles['stdout'].close()
    return result, content
    # Process GnuPG status one line at a time
    is_encrypted = False
    lines = result.split('\n')
    for line in lines:
        # GnuPG status lines begin with "gpg: "
        if line.startswith("gpg: "):
            if "public key not found" in line:
                # This condition could indicate a new request, signed with
                # the newly created key that we don't know yet.
                return 001, None, content
            if ("CRC error" in line or
                "no valid OpenPGP data found" in line or
                "unexpected data" in line):
                # These are a collection of decrypt failure messages that
                # should result in an exit.
                return 301, line, None
            if "encrypted with" in line:
                is_encrypted = True
            if "Bad signature" in line:
                return 401, line, None
            if "Good signature" in line:
                # This test is harsh.  It assumes that the addresses will be
                # on the same line as the "Good signature".  There are valid
                # instances where this isn't True but we tell key creators to
                # not create keys with multi-uids.
                address = email_re.search(line)
                if address:
                    return 001, address.group(0), content
    if is_encrypted:
        # Messages is encrytped but not signed.  Probably a new Nym request.
        return 001, None, content
    logmsg = "GnuPG returned nothing we understand.\n%s" % result
    return 401, logmsg, None

def decrypt(message, passphrase):
    """Decrypt a PGP message and return it in plain text."""
    gnupg.options.armor = 1
    gnupg.options.meta_interactive = 0
    gnupg.options.always_trust = 1
    gnupg.options.homedir = KEYRING
    gnupg.passphrase = passphrase
    proc = gnupg.run(['--decrypt'], create_fhs=['stdin', 'stdout', 'logger'])
    proc.handles['stdin'].write(message)
    proc.handles['stdin'].close()
    result = proc.handles['logger'].read()
    content = proc.handles['stdout'].read()
    proc.handles['logger'].close()
    proc.handles['stdout'].close()
    return 001, content

def verify_decrypt(message, passphrase):
    """This function is unusual in that it returns 3 variables:
    Return Code, Result (Email if verified), Decrypted Payload."""
    gnupg.options.armor = 1
    gnupg.options.meta_interactive = 0
    gnupg.options.always_trust = 1
    gnupg.options.homedir = KEYRING
    gnupg.passphrase = passphrase
    proc = gnupg.run(['--decrypt'], create_fhs=['stdin', 'stdout', 'logger'])
    proc.handles['stdin'].write(message)
    proc.handles['stdin'].close()
    result = proc.handles['logger'].read()
    content = proc.handles['stdout'].read()
    proc.handles['logger'].close()
    proc.handles['stdout'].close()
    # Process GnuPG status one line at a time
    is_encrypted = False
    lines = result.split('\n')
    for line in lines:
        # GnuPG status lines begin with "gpg: "
        if line.startswith("gpg: "):
            if "public key not found" in line:
                # This condition could indicate a new request, signed with
                # the newly created key that we don't know yet.
                return 001, None, content
            if ("CRC error" in line or
                "no valid OpenPGP data found" in line or
                "unexpected data" in line):
                # These are a collection of decrypt failure messages that
                # should result in an exit.
                return 301, line, None
            if "encrypted with" in line:
                is_encrypted = True
            if "Bad signature" in line:
                return 401, line, None
            if "Good signature" in line:
                # This test is harsh.  It assumes that the addresses will be
                # on the same line as the "Good signature".  There are valid
                # instances where this isn't True but we tell key creators to
                # not create keys with multi-uids.
                address = email_re.search(line)
                if address:
                    return 001, address.group(0), content
    if is_encrypted:
        # Messages is encrytped but not signed.  Probably a new Nym request.
        return 001, None, content
    logmsg = "GnuPG returned nothing we understand.\n%s" % result
    return 401, logmsg, None

def decrypt(message, passphrase):
    """Decrypt a PGP message and return it in plain text."""
    gnupg.options.armor = 1
    gnupg.options.meta_interactive = 0
    gnupg.options.always_trust = 1
    gnupg.options.homedir = KEYRING
    gnupg.passphrase = passphrase
    proc = gnupg.run(['--decrypt'], create_fhs=['stdin', 'stdout', 'logger'])
    proc.handles['stdin'].write(message)
    proc.handles['stdin'].close()
    result = proc.handles['logger'].read()
    content = proc.handles['stdout'].read()
    proc.handles['logger'].close()
    proc.handles['stdout'].close()
    return 001, content

def symmetric(passphrase, payload):
    """Symmetric encryption seems to choke stdout when handling large files.
    To overcome this issue, I'm using tempfile to write the output to file
    instead of stdout."""
    temp = tempfile.TemporaryFile()
    optlist = ['--cipher-algo', 'AES256']
    gnupg.options.armor = 1
    gnupg.options.meta_interactive = 0
    gnupg.passphrase = passphrase
    gnupg.options.extra_args = optlist
    gnupg.options.extra_args.append('--no-version')
    proc = gnupg.run(['--symmetric'], create_fhs=['stdin'],
                                      attach_fhs={'stdout': temp})
    proc.handles['stdin'].write(payload)
    proc.handles['stdin'].close()
    proc.wait()
    temp.seek(0)
    return temp.read()

def Encrypt(recipient, payload):
    recipients = []
    recipients.append(recipient)
    gnupg.options.armor = 1
    gnupg.options.meta_interactive = 0
    gnupg.options.always_trust = 1
    gnupg.options.recipients = recipients
    gnupg.options.homedir = PUBRING
    proc = gnupg.run(['--encrypt'], create_fhs=['stdin', 'stdout'])
    proc.handles['stdin'].write(payload)
    proc.handles['stdin'].close()
    ciphertext = proc.handles['stdout'].read()
    proc.handles['stdout'].close()
    return ciphertext

def signcrypt(recipient, senderkey, passphrase, payload, throw_key = False):
    recipients = []
    recipients.append(recipient)
    gnupg.options.armor = 1
    gnupg.options.meta_interactive = 0
    gnupg.options.always_trust = 1
    #gnupg.options.no_version = 1
    gnupg.options.recipients = recipients
    gnupg.options.default_key = senderkey
    gnupg.options.homedir = KEYRING
    gnupg.options.extra_args.append('--no-version')
    if throw_key:
        gnupg.options.extra_args.append('--throw-keyid')
    gnupg.passphrase = passphrase
    proc = gnupg.run(['--encrypt', '--sign'], create_fhs=['stdin', 'stdout'])
    proc.handles['stdin'].write(payload)
    proc.handles['stdin'].close()
    ciphertext = proc.handles['stdout'].read()
    proc.handles['stdout'].close()
    proc.wait()
    return ciphertext

def GenKey(name, addy, passphrase):
    print "Generating new key %s <%s>" % (name, addy)
    gnupg.options.armor = 1
    gnupg.options.meta_interactive = 0
    gnupg.options.homedir = PUBRING
    proc = gnupg.run(['--gen-key'], create_fhs=['stdin', 'stdout', 'logger', 'status'])
    proc.handles['stdin'].write("Key-Type: DSA\n")
    proc.handles['stdin'].write("Key-Length: 1024\n")
    #proc.handles['stdin'].write("%dry-run\n")
    proc.handles['stdin'].write("Subkey-Type: ELG-E\n")
    proc.handles['stdin'].write("Subkey-Length: 1024\n")
    proc.handles['stdin'].write("Name-Real: %s\n" % name)
    proc.handles['stdin'].write("Name-Email: %s\n" % addy)
    proc.handles['stdin'].write("Expire-Date: 2y\n")
    proc.handles['stdin'].write("Passphrase: %s\n" % passphrase)
#    proc.handles['stdin'].write("%pubring nympub.gpg\n")
#    proc.handles['stdin'].write("%secring nymsec.gpg\n")
    proc.handles['stdin'].close()
    report = proc.handles['logger'].read()
    proc.handles['logger'].close()
    status = proc.handles['status'].read()
    proc.handles['status'].close()
    #proc.wait()
    
    # Now we need to scan the status output and search for the line
    # containing the KEY_CREATED output.  Messy, but it appears to be
    # the only way to do this.
    for line in status.split("\n"):
        keyid_re = re.search(r'KEY_CREATED\s+(\w+)\s+(\w+)\b', line)
        if keyid_re:
            keyid = keyid_re.group(2)
            break
    return keyid

def ValidateEmail(recipient):
    """Check if the recipient is a valid email address."""
    if re.match(r'[\w\-][\w\-\.]*@[\w\-][\w\-\.]+[a-zA-Z]{1,4}', recipient):
        return True
    else:
        return False

def GetKeyID(email):
    # Try and get the Nym keyid.  If it doesn't exist then generate it.
    existing = CheckKey(email)
    if existing:
        options['nym-keyid'] = existing
    else:
        options['nym-keyid'] = GenKey(options['nym-name'],
                                      options['nym-email'],
                                      options['nym-passphrase'])
    return options

def CheckKey(email):
    """Getting the long keyid is tricky. It's the fingerprint without spaces.
    We attempt to retreive the fingerprint. If we can, we strip the spaces out
    and return the result. If we can't get the fingerprint, we return False."""
    fp = Fingerprint(email)
    if not fp:
        return False
    else:
        keyid = fp.replace(' ','')
    return keyid

class GpgStatParse():
    """Here we try and make sense out of the GnuPG Statuses returned from the
    various GnuPG operations."""

    def __init__(self):
        """Define all the regular expressions required to populate the GnuPG
        Status dictionary."""
        # gpg: encrypted with 2048-bit ELG-E key, ID F207AEDB, created 2003-06-04
        enc = "gpg: encrypted with (\d+)-bit"
        enc += " (\S+) key"
        enc += ".*ID ([0-9A-F]+)"
        enc += ".*created ([0-9\-]+)$"
        enc_re = re.compile(enc)
        # gpg: decryption failed: secret key not available
        decfail_re = re.compile("gpg: decryption failed: (.*)")
        # gpg: public key decryption failed: bad passphrase
        pkdfail_re = re.compile("gpg: public key decryption failed: (.*)")
        # gpg: Good signature from "Steven Crook"
        goodsig_re = re.compile("gpg: Good signature from \"(.*)\"")
        # gpg:                 aka "Steven Crook <steve@mixmin.net>"
        akasig_re = re.compile("gpg: +aka \"(.*)\"")
        # gpg: Signature made Sun 10 Jul 2011 12:02:04 BST using DSA key ID 228761E7
        sigmade = "gpg: Signature made (.*) using (.*) ID ([0-9A-F]+)"
        sigmade_re = re.compile(sigmade)
        # pub   1024D/228761E7 2003-06-04
        pub_re = re.compile("pub +([^/]+)/([0-9A-F]+) ([0-9\-]+)")
        # sub   1024D/228761E7 2003-06-04
        sub_re = re.compile("sub +([^/]+)/([0-9A-F]+) ([0-9\-]+)")
        # gpg: WARNING: Using untrusted key!
        nottrusted = "gpg: WARNING: Using untrusted key!"
        # Match a valid email address
        # TODO: This regex is too generic to be in here.
        email_re = re.compile('([\w\-][\w\-\.]*)@[\w\-][\w\-\.]+[a-zA-Z]{1,4}')

        self.enc_re = enc_re
        self.decfail_re = decfail_re
        self.pkdfail_re = pkdfail_re
        self.goodsig_re = goodsig_re
        self.akasig_re = akasig_re
        self.sigmade_re = sigmade_re
        self.email_re = email_re
        self.nottrusted = nottrusted
        self.pub_re = pub_re
        self.sub_re = sub_re

    def __strip_gpg(self, text):
        gpg, rest = text.split(": ", 1)
        return rest

    def __epoch_from_datestr(self, datestr):
        """Return epoch seconds when passed a date string formatted as:
        2011-07-11.  GnuPG seems to use this format for key dates."""
        pattern = '%Y-%m-%d'
        return int(time.mktime(time.strptime(datestr, pattern)))


    def statparse(self, status):
        """Take a GnuPG Status message and parse it into specific dictionary
        elements. We might not capture every possible element but at least all
        those we need to perform effective validation."""
        # All status lines begin with gpg: but we'll let the regexs take care
        # of that for us.
        lines = status.split("\n")
        gpgstat = {} # Dictionary of GPG status that we'll return
        gpgstat['uidtext'] = [] # List of plain-text uids
        gpgstat['uidmail'] = [] # List of email addresses in uids
        for line in lines:
            # First we'll look for errors as there's no point populating a
            # dict that's not returned.
            # gpg: CRC error; 44FB85 - C2B77E
            if line.startswith("gpg: CRC error"):
                err = self.__strip_gpg(line)
                raise GnupgError(err)

            enc_match = self.enc_re.match(line)
            if enc_match:
                gpgstat['ekeylen'] = enc_match.group(1)
                gpgstat['ekeytype'] = enc_match.group(2)
                gpgstat['ekeyid'] = enc_match.group(3)
                encdate = enc_match.group(4)
                gpgstat['ekeydate'] = self.__epoch_from_datestr(encdate)

            sigmade_match = self.sigmade_re.match(line)
            if sigmade_match:
                # We attempt to convert the signature date to seconds since
                # epoch format.
                sigdate = sigmade_match.group(1)
                sigepoch = email.utils.parsedate(sigdate)
                gpgstat['sigdate'] = time.mktime(sigepoch)
                gpgstat['sigtype'] = sigmade_match.group(2)
                gpgstat['sigkeyid'] = sigmade_match.group(3)

            decfail_match = self.decfail_re.match(line)
            if decfail_match:
                gpgstat['decfail'] = True
                gpgstat['decfailreason'] = decfail_match.group(1)

            pkdfail_match = self.pkdfail_re.match(line)
            if pkdfail_match:
                gpgstat['pkdfail'] = True
                gpgstat['pkdfailreason'] = pkdfail_match.group(1)

            goodsig_match = self.goodsig_re.match(line)
            if goodsig_match:
                gpgstat['goodsig'] = True
                txt = goodsig_match.group(1)
                gpgstat['uidtext'].append(txt)
                # Perform a sub-match on the sig text to see if it contains a
                # valid email address.
                goodsigmail_match = self.email_re.search(txt)
                if goodsigmail_match:
                    gpgstat['uidmail'].append(goodsigmail_match.group(0))

            akasig_match = self.akasig_re.match(line)
            # AKA signatures always follow from Good signature lines, so wise
            # to validate that we've already seen Good signature.
            if 'goodsig' in gpgstat and gpgstat['goodsig'] and akasig_match:
                txt = akasig_match.group(1)
                gpgstat['goodsigtext'].append(txt)
                # Perform a sub-match on the sig text to see if it contains a
                # valid email address.
                akasigmail_match = self.email_re.search(txt)
                if akasigmail_match:
                    gpgstat['goodsigmail'].append(akasigmail_match.group(0))

            # UID lines
            if line.startswith("uid"):
                foo, uid = line.split(" ", 1)
                uid = uid.strip()
                gpgstat['uidtext'].append(uid)
                uidmail_match = self.email_re.search(uid)
                if uidmail_match:
                    gpgstat['uidmail'].append(uidmail_match.group(0))

            # PUB lines
            pub_match = self.pub_re.match(line)
            if pub_match:
                gpgstat['sigtype'] = pub_match.group(1)
                gpgstat['sigkeyid'] = pub_match.group(2)
                sigdate = pub_match.group(3)
                gpgstat['sigdate'] = self.__epoch_from_datestr(sigdate)

            # SUB lines
            sub_match = self.sub_re.match(line)
            if sub_match:
                gpgstat['subtype'] = sub_match.group(1)
                gpgstat['subkeyid'] = sub_match.group(2)
                sigdate = sub_match.group(3)
                gpgstat['subdate'] = self.__epoch_from_datestr(sigdate)

            if line == self.nottrusted:
                gpgstat['trusted'] = False
        return gpgstat

def main():
    msg = """\
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.11 (GNU/Linux)

hQIOA6U5QbvyB67bEAf/csnvPQl07WU/bmlPEqoJL9eML9sesLi3toNfdYEtjcKZ
rOgOURvmD6czfZ3u8kWfbBHsWoMINQ8c1dhxE5NCZoS1+ur5aZzAhaUFZj86MFph
zGccPN3d/wifzJX8mEK008plza29dq72z9sHRBhFjiEF+I6ULrPuTxT96DlOFFxc
aUImOLYvK87c2kHdCexalaDqPEDe9N/Lsc6aKCKF0FBTvy55ODp19X9NHozasmL+
Y8SSbO21ZlhcHghNkr+89KU21APCrR0U5yCSGLQZeL/jxcIcfi7MwKzN3zzBhoPK
pgVNzyOTaOliIN9eGQRCzq1PsAg3EM+uVJeu0a/1+Af/cXOSSrqwQDvjlJCLfOry
lCCaaTIQO6xYPZvxJqB995Ds5R34nVqV6bnNkzu1Oqd2pHoagCsQZBTu7h7t6U+g
azkN4DEDJWaLjPX9gB1uwq656qFa5fIp4KRHBMpOOkOPiAb3VCxsRlD96dMvej6z
vHkx/a8Rg04nCv5DZuNjLNzvXql64lFE+qZ8GMWQFayORduLkzkEVkogA3mroh3r
oOF/3hVSkpKTF9AchG7uD7NQG7V5BmS0FJWxy7ag/6v0fBxhKrY5wl4LsNZ4qd6y
G71y90w2iLwp10/6GeqKSiDCbtCGruMhDVk+xOasb7rRXS9wbow9qu5hQmL/OioY
ktKlAZnt/KNHTymAoSYP5n/iUtQKn+Xja+UnMWDnnaoeYITtUdOfItXSvWos+cvo
Ceb+sRJxf9NICaKg3ajH21SCeF82jIIDUSXiVoRcgJlW2tUnwNjDMFFlQAHOHzdP
jTGz10pe8Uat8s3sFzYRhpu7gO26GcU/96jnsMrALVWEnhpYqNq7i/2Tvwktd3PK
kR06JJLOrLHoS9yMLXC0EHShs6+VWRru
=wrd+
-----END PGP MESSAGE----- """
    foo = GnuPG()
    gnupg = gpgFunctions()
    g = GpgStatParse()
    status =  gnupg.keyinfo("228761e7")
    print status
    print "------"
    gpgstat = g.statparse(status)
    for k in gpgstat:
        print "%s: %s" % (k, gpgstat[k])

# Call main function.
if (__name__ == "__main__"):
    main()
