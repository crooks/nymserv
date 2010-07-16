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

import GnuPGInterface
import re
import tempfile

gnupg = GnuPGInterface.GnuPG()
KEYRING = '/crypt/home/nymserv/keyring'
email_re = re.compile('([\w\-][\w\-\.]*)@[\w\-][\w\-\.]+[a-zA-Z]{1,4}')

def export(keyid):
    gnupg.options.armor = 1
    gnupg.options.meta_interactive = 0
    gnupg.options.homedir = KEYRING
    idlist = []
    idlist.append(keyid)
    proc = gnupg.run(['--export'], args=idlist, create_fhs=['stdout'])
    key = proc.handles['stdout'].read()
    proc.handles['stdout'].close()
    proc.wait()
    return key

def get_email_from_keyid(keyid):
    gnupg.options.armor = 1
    gnupg.options.meta_interactive = 0
    gnupg.options.homedir = KEYRING
    idlist = []
    idlist.append(keyid)
    proc = gnupg.run(['--list-keys'], args=idlist, create_fhs=['stdout'])
    result = proc.handles['stdout'].read()
    proc.handles['stdout'].close()
    proc.wait()
    is_email = re.search(email_re, result)
    if is_email:
        return 001, is_email.group(0)
    return 301, 'Unable to extract email address from key'

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
            addresses.append(is_email.group(1))
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

def import_file(file):
    """Import a PGP key and if successful, return its Fingerprint"""
    filelist = []
    filelist.append(file)
    gnupg.options.meta_interactive = 0
    gnupg.options.homedir = KEYRING
    proc = gnupg.run(['--import'], args=filelist, create_fhs=['logger'])
    result = proc.handles['logger'].read()
    proc.handles['logger'].close()
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
    lines = result.split('\n')
    for line in lines:
        address = email_re.search(line)
        if not address:
            continue
        sigfor = address.group(0)
        if 'Good signature' in line:
            return 001, sigfor
        if 'BAD signature' in line:
            return 301, 'Bad signature for ' + sigfor + '.'
    return 301, 'No signature found during verify operation.'

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
    try:
        proc.wait()
    except IOError:
        return 301, 'Invalid PGP Message.', None
    lines = result.split('\n')
    for line in lines:
        address = email_re.search(line)
        if not address:
            continue
        sigfor = address.group(0)
        if 'Good signature' in line:
            return 001, sigfor, content
        if 'BAD signature' in line:
            return 301, 'Bad signature for ' + sigfor + '.', None
    return 301, 'No signature found during verify operation.', None

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

def main():
    None

# Call main function.
if (__name__ == "__main__"):
    main()
