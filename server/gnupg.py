#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 autoindent
#
# gnupg.py - GnuPG functionality through GnuPGInterface.
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

import GnuPGInterface
import re
import tempfile
import os.path
import email.utils
import time

class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class GnupgError(Error):
    """GnuPG Verification Errors"""
    def __init__(self, expr):
        self.expr = expr
    def __str__(self):
        return repr(self.expr)

# Superclass GnuPGInterface.GnuPG
class GnuPGFunctions():
    
    def __init__(self, keyring = None):
        self.gnupg = GnuPGInterface.GnuPG()
        # Process our subclass __init__
        if keyring is None:
            homedir = os.path.expanduser('~')
            keyring = os.path.join(homedir, '.gnupg')
        if not os.path.isdir(keyring):
            raise GnupgError("Keyring directory not found.")
        self.keyring = keyring
        self.email_re = \
          re.compile('([\w\-][\w\-\.]*)@[\w\-][\w\-\.]+[a-zA-Z]{1,4}')
        
    def reset_options(self):
        self.gnupg.options = GnuPGInterface.Options()
        # Override some of GnuPGInterface's options with those we require.
        self.gnupg.options.armor = 1
        self.gnupg.options.meta_interactive = 0
        self.gnupg.options.homedir = self.keyring
        self.gnupg.options.always_trust = 1

    def decrypt_verify(self, message, passphrase):
        """This function is unusual in that it returns 3 variables:
        Return Code, Result (Email if verified), Decrypted Payload."""
        self.reset_options()
        self.gnupg.options.extra_args = ['--with-fingerprint']
        self.gnupg.passphrase = passphrase
        proc = self.gnupg.run(['--decrypt'], create_fhs=['stdin',
                                                   'stdout',
                                                   'logger'])
        proc.handles['stdin'].write(message)
        proc.handles['stdin'].close()
        result = proc.handles['logger'].read()
        content = proc.handles['stdout'].read()
        proc.handles['logger'].close()
        proc.handles['stdout'].close()
        # We need to trap decrypt failures, otherwise execution aborts with
        # a traceback, just because we can't decrypt a message.
        try:
            proc.wait()
        except IOError, e:
            pass
        return result, content

    def export(self, keyid):
        self.reset_options()
        idlist = [keyid]
        proc = self.gnupg.run(['--export'], args=idlist, create_fhs=['stdout',
                                                                    'logger'])
        result = proc.handles['logger'].read()
        key = proc.handles['stdout'].read()
        proc.handles['stdout'].close()
        proc.wait()
        # result isn't returned as it doesn't mean much from an export.
        return key

    def keyinfo(self, keyid):
        """Takes a single keyid and returns all the info from list-keys that
        relate to it. The related fingerprint is also returned."""
        self.reset_options()
        self.gnupg.options.extra_args = ['--with-fingerprint']
        idlist = [keyid]
        proc = self.gnupg.run(['--list-keys'], args=idlist,
                                               create_fhs=['stdout'])
        result = proc.handles['stdout'].read()
        proc.handles['stdout'].close()
        return result

    def fingerprint(self, keyid):
        """Return a single fingerprint in response to a keyid or email.
        If more than one fingerprint is return from the supplied criteria,
        None is returned.  This prevents potential ambiguity."""
        self.reset_options()
        idlist = [keyid]
        proc = self.gnupg.run(['--fingerprint'], args=idlist,
                                                 create_fhs=['stdout'])
        result = proc.handles['stdout'].read()
        proc.handles['stdout'].close()
        lines = result.split("\n")
        fps = []
        lastline = ""
        for line in lines:
            if "Key fingerprint" in line and lastline.startswith("pub"):
                foo, fp = line.split(" = ")
                fpc = fp.replace(" ", "")
                fps.append(fpc)
            lastline = line
        if len(fps) == 1:
            return fps[0]
        return None

    def emails_to_list(self):
        """This is a kludge, but a useful one.  It returns a list of all the
        uid pulic email addresses on a keyring."""
        self.reset_options()
        proc = self.gnupg.run(['--list-keys'], create_fhs=['stdout'])
        result = proc.handles['stdout'].read()
        proc.handles['stdout'].close()
        proc.wait()
        uidmail = []
        # UID lines
        lines = result.split("\n")
        for line in lines:
            if line.startswith("uid"):
                foo, uid = line.split(" ", 1)
                uid = uid.strip()
                uidmail_match = self.email_re.search(uid)
                if uidmail_match:
                    uidmail.append(uidmail_match.group(0))
        return uidmail

    def delete_key(self, keyid):
        """Delete a public key. Note: This doesn't return a status. It either
        succeeds or it errors.  Simples!"""
        #TODO Not tested this yet.
        self.reset_options()
        idlist = [keyid]
        proc = self.gnupg.run(['--delete-key'], args=idlist)
        proc.wait()

    def import_key(self, key, dryrun = False):
        """Import a PGP key and if successful, return its Fingerprint.  The
        dry-run option on import is useless for some purposes as it doesn't
        report the uid's on the key.  We want more than this so we have our
        own dry-run function that imports to a tempfile."""
        keyfile = tempfile.NamedTemporaryFile()
        keyfile.write(key)
        keyfile.seek(0)
        filelist = [keyfile.name]
        self.reset_options()
        self.gnupg.options.extra_args = ['--with-fingerprint']
        if dryrun:
            self.gnupg.options.extra_args.append('--no-default-keyring')
            self.gnupg.options.extra_args.append('--keyring')
            self.gnupg.options.extra_args.append('tmpring.gpg')
        proc = self.gnupg.run(['--import'], args=filelist,
                                            create_fhs=['logger'])
        result = proc.handles['logger'].read()
        proc.handles['logger'].close()
        keyfile.close()
        try:
            proc.wait()
        except IOError, e:
            pass
        return result

    def verify(self, message):
        self.reset_options()
        self.gnupg.options.extra_args = ['--with-fingerprint']
        proc = self.gnupg.run(['--verify'], create_fhs=['stdin', 'logger'])
        proc.handles['stdin'].write(message)
        proc.handles['stdin'].close()
        result = proc.handles['logger'].read()
        proc.handles['logger'].close()
        return result

    def symmetric(self, passphrase, payload):
        """Symmetric encryption seems to choke stdout when handling large
        files.  To overcome this issue, I'm using tempfile to write the output
        to file instead of stdout."""
        temp = tempfile.TemporaryFile()
        self.gnupg.passphrase = passphrase
        self.reset_options()
        self.gnupg.options.extra_args = ['--cipher-algo', 'AES256']
        #self.gnupg.options.extra_args.append('--no-version')
        proc = self.gnupg.run(['--symmetric'], create_fhs=['stdin'],
                                         attach_fhs={'stdout': temp})
        proc.handles['stdin'].write(payload)
        proc.handles['stdin'].close()
        proc.wait()
        temp.seek(0)
        ciphertext = temp.read()
        temp.close()
        return ciphertext

    def signcrypt(self, recipient, senderkey, passphrase, payload,
                  throw_key = False):
        temp = tempfile.TemporaryFile()
        recipients = [recipient]
        self.reset_options()
        self.gnupg.options.recipients = recipients
        self.gnupg.options.default_key = senderkey
        self.gnupg.options.extra_args = []
        if throw_key:
            self.gnupg.options.extra_args.append('--no-version')
            self.gnupg.options.extra_args.append('--throw-keyid')
        self.gnupg.passphrase = passphrase
        proc = self.gnupg.run(['--encrypt', '--sign'],
                                               create_fhs=['stdin', 'logger'],
                                               attach_fhs={'stdout': temp})
        proc.handles['stdin'].write(payload)
        proc.handles['stdin'].close()
        result = proc.handles['logger'].read()
        proc.handles['logger'].close()
        try:
            proc.wait()
        except IOError, e:
            return result, None
        temp.seek(0)
        ciphertext = temp.read()
        temp.close()
        return result, ciphertext

    def encrypt(self, recipient, payload):
        recipients = [recipient]
        self.reset_options()
        self.gnupg.options.recipients = recipients
        proc = self.gnupg.run(['--encrypt'], create_fhs=['stdin', 'stdout'])
        proc.handles['stdin'].write(payload)
        proc.handles['stdin'].close()
        ciphertext = proc.handles['stdout'].read()
        proc.handles['stdout'].close()
        proc.wait()
        return ciphertext

class GnuPGStatParse():
    """Here we try and make sense out of the GnuPG Statuses returned from the
    various GnuPG operations. The only public function that should be called
    is statparse which takes a single arguement: the GnuPG status output.
    
    Output from statparse is a dictionary object containing all the pertinent
    information the function could aquire from the status text.
    
    Example:
    gpg = GnupgFunctions()
    gpgparse = GnupgStatParse()
    status = gpg.keyinfo("228761E7")
    keyinfo = gpgparse.statparse(status)
    sys.stdout.write("Fingerprint: %(fingerprint)s" % keyinfo)
    """

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
        sigmade = "gpg: Signature made (.*) using (.*) key ID ([0-9A-F]+)"
        sigmade_re = re.compile(sigmade)
        
        # pub   1024D/228761E7 2003-06-04
        pub_re = re.compile("pub +([^/]+)/([0-9A-F]+) ([0-9\-]+)")
        
        # sub   1024D/228761E7 2003-06-04
        sub_re = re.compile("sub +([^/]+)/([0-9A-F]+) ([0-9\-]+)")
        
        # Key fingerprint = 1CD9 95E1 E9CE 80D6 C885  B7EB B471 80D5 2287 61E7
        # Primary key fingerprint: 0123 4567 89AB CDEF
        fingerprint_re = re.compile("fingerprint[ :=]+([0-9A-F ]{40,})")
        
        # gpg: WARNING: Using untrusted key!
        nottrusted = "gpg: WARNING: Using untrusted key!"
        
        # Match a valid email address
        # TODO: This regex is too generic to be in here.
        email_re = re.compile('([\w\-][\w\-\.]*)@[\w\-][\w\-\.]+[a-zA-Z]{1,4}')
        
        # This one is returned on key imports
        # gpg: Total number processed: 0
        imported = "gpg: Total number processed: "

        # gpg: key 1E49F7D8: public key "oo7 <oo7@mixnym.net>" imported
        imp = "gpg: key ([0-9A-F]+): public key \"(.*)\" imported"
        import_re = re.compile(imp)
        #gpg: key 50343676: "Flump (Flump Nym) <flump@mixnym.net>" not changed
        imp = "gpg: key ([0-9A-F]+): \"(.*)\" not changed"
        import_nc_re = re.compile(imp)

        # gpg: verify signatures failed: unexpected data
        verifyfail = "gpg: verify signatures failed"

        self.enc_re = enc_re
        self.decfail_re = decfail_re
        self.pkdfail_re = pkdfail_re
        self.goodsig_re = goodsig_re
        self.akasig_re = akasig_re
        self.sigmade_re = sigmade_re
        self.email_re = email_re
        self.nottrusted = nottrusted
        self.imported = imported
        self.import_re = import_re
        self.import_nc_re = import_nc_re
        self.import_novalid_re = re.compile(imp)
        self.pub_re = pub_re
        self.sub_re = sub_re
        self.fingerprint_re = fingerprint_re
        self.verifyfail = verifyfail

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
        lastline = None
        gpgstat = {} # Dictionary of GPG status that we'll return
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
                gpgstat['keyid'] = sigmade_match.group(3)

            fingerprint_match = self.fingerprint_re.search(line)
            # Check for lastline prevents picking up the fingerprint for subkey
            # instead of the primary.
            if fingerprint_match and not lastline.startswith("sub"):
                fp = fingerprint_match.group(1)
                gpgstat['fingerprint'] = fp.replace(" ", "")

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
                if 'uidtext' not in gpgstat:
                    gpgstat['uidtext'] = []
                gpgstat['uidtext'].append(txt)

                # Perform a sub-match on the sig text to see if it contains a
                # valid email address.
                goodsigmail_match = self.email_re.search(txt)
                if goodsigmail_match:
                    if 'uidmail' not in gpgstat:
                        gpgstat['uidmail'] = []
                    gpgstat['uidmail'].append(goodsigmail_match.group(0))

            # AKA lines in key signatures
            akasig_match = self.akasig_re.match(line)
            if akasig_match:
                txt = akasig_match.group(1)
                if 'uidtext' not in gpgstat:
                    # This should never happen.  Can't get an aka without first
                    # having processed a signature. Processing that signature
                    # would create the 'uidtext' element.
                    raise GnupgError("Unexpected aka before signature")
                gpgstat['uidtext'].append(txt)
                # Perform a sub-match on the sig text to see if it contains a
                # valid email address.
                akasigmail_match = self.email_re.search(txt)
                if akasigmail_match:
                    if 'uidmail' not in gpgstat:
                        # This is a valid condition because the Signature line
                        # might contain a non-email uid.
                        gpgstat['uidmail'] = []
                    gpgstat['uidmail'].append(akasigmail_match.group(0))

            # UID lines
            if line.startswith("uid"):
                foo, uid = line.split(" ", 1)
                uid = uid.strip()
                if 'uidtext' not in gpgstat:
                    gpgstat['uidtext'] = []
                gpgstat['uidtext'].append(uid)
                uidmail_match = self.email_re.search(uid)
                if uidmail_match:
                    if 'uidmail' not in gpgstat:
                        gpgstat['uidmail'] = []
                    gpgstat['uidmail'].append(uidmail_match.group(0))

            # PUB lines
            pub_match = self.pub_re.match(line)
            if pub_match:
                gpgstat['sigtype'] = pub_match.group(1)
                gpgstat['keyid'] = pub_match.group(2)
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

            if line.startswith(self.imported):
                foo, numpro = line.split("processed: ")
                gpgstat['imported'] = int(numpro)

            # Importing keys
            import_match = self.import_re.match(line)
            import_nc_match = self.import_nc_re.match(line)
            if import_match:
                gpgstat['keyid'] = import_match.group(1)
                uid = import_match.group(2)
            if import_nc_match:
                gpgstat['keyid'] = import_nc_match.group(1)
                uid = import_nc_match.group(2)
            if import_match or import_nc_match:
                if 'uidtext' not in gpgstat:
                    gpgstat['uidtext'] = []
                gpgstat['uidtext'].append(uid)
                email_match = self.email_re.search(uid)
                if email_match:
                    if 'uidmail' not in gpgstat:
                        gpgstat['uidmail'] = []
                    gpgstat['uidmail'].append(email_match.group(0))

            # Verify Failure
            if line.startswith(self.verifyfail):
                gpgstat['goodsig'] = False
            # In some instances, (like fingerprint) we need to check the
            # previous line to get the correct match.
            lastline = line
        return gpgstat

def main():
    g = GnuPGFunctions("/crypt/var/nymserv/keyring")
    gp = GnuPGStatParse()
    txt = "The cat sat on the matress"
    print g.symmetric("foo", txt)
    g.reset_options()

# Call main function.
if (__name__ == "__main__"):
    main()
