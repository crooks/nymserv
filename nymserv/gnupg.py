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
    pass


class DecryptError(Error):
    """GnuPG Decrypt Errors"""
    def __init__(self, expr):
        self.expr = expr

    def __str__(self):
        return repr(self.expr)


class PGPKeyError(Error):
    """Generic issues related to keys and their fields."""
    def __init__(self, expr):
        self.expr = expr

    def __str__(self):
        return repr(self.expr)


class GnuPGFunctions():
    def __init__(self, keyring=None):
        self.gnupg = GnuPGInterface.GnuPG()
        # Process our subclass __init__
        if keyring is None:
            homedir = os.path.expanduser('~')
            keyring = os.path.join(homedir, '.gnupg')
        if not os.path.isdir(keyring):
            raise IOError("PGP Keyring directory not found")
        self.keyring = keyring
        self.email_re = re.compile(
                '([\w\-][\w\-\.]*)@[\w\-][\w\-\.]+[a-zA-Z]{1,4}')

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
        temp = tempfile.TemporaryFile()
        self.reset_options()
        self.gnupg.options.extra_args = ['--with-fingerprint']
        self.gnupg.options.extra_args.append('--pinentry-mode=loopback')
        self.gnupg.passphrase = passphrase
        proc = self.gnupg.run(['--decrypt'],
                              create_fhs=['stdin', 'logger'],
                              attach_fhs={'stdout': temp})
        proc.handles['stdin'].write(message)
        proc.handles['stdin'].close()
        result = proc.handles['logger'].read()
        proc.handles['logger'].close()
        # We need to trap decrypt failures, otherwise execution aborts with
        # a traceback, just because we can't decrypt a message.
        try:
            proc.wait()
        except IOError, e:
            pass
        temp.seek(0)
        content = temp.read()
        temp.close()
        return result, content

    def export(self, keyid):
        self.reset_options()
        idlist = [keyid]
        proc = self.gnupg.run(['--export'],
                              args=idlist,
                              create_fhs=['stdout', 'logger'])
        result = proc.handles['logger'].read()
        key = proc.handles['stdout'].read()
        proc.handles['stdout'].close()
        proc.handles['logger'].close()
        proc.wait()
        # result isn't returned as it doesn't mean much from an export.
        return key

    def keyinfo(self, keyid):
        """Takes a single keyid and returns all the info from list-keys that
        relate to it. The related fingerprint is also returned."""
        self.reset_options()
        self.gnupg.options.extra_args = ['--with-fingerprint']
        idlist = [keyid]
        proc = self.gnupg.run(['--list-keys'],
                              args=idlist,
                              create_fhs=['stdout', 'logger'])
        result = proc.handles['stdout'].read()
        proc.handles['stdout'].close()
        proc.handles['logger'].close()
        return result

    def fingerprint(self, keyid):
        """Return a single fingerprint in response to a keyid or email.
        If more than one fingerprint is return from the supplied criteria,
        None is returned.  This prevents potential ambiguity."""
        self.reset_options()
        # Comparing keyids is easier if they're all the same case.
        keyid = keyid.upper()
        idlist = [keyid]
        proc = self.gnupg.run(['--with-colons', '--fingerprint'],
                              args=idlist,
                              create_fhs=['stdout', 'logger'])
        result = proc.handles['stdout'].read()
        err = proc.handles['logger'].read()
        proc.handles['stdout'].close()
        proc.handles['logger'].close()
        lines = result.split("\n")
        if len(err) > 0:
            raise PGPKeyError(err)
        pub = None  # Public Key
        fpr = None  # Fingerprint
        # Parsing pub and fpr in the same loop is feasible because pub will
        # always preceed fpr in gpg output.
        for line in lines:
            if line.startswith('pub'):
                pub = line.split(":")[4]
                if not pub.endswith(keyid):
                    pub = None
            if pub is not None and line.startswith('fpr'):
                fpr = line.split(":")[9]
                if fpr.endswith(pub):
                    # The fpr matches the pub so break out and return the fpr.
                    break
                else:
                    # fpr doesn't match the pub, keep iterating.
                    fpr = None
        if pub is None:
            raise PGPKeyError(
                    "No Public Key found matching KeyID: {}".format(keyid))
        if fpr is None:
            raise PGPKeyError(
                    "No fingerprint found matching PubKey: {}".format(pub))
        return fpr

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

    def listkeys(self):
        """Return a list of all the keys on the keyring."""
        self.reset_options()
        proc = self.gnupg.run(['--list-keys'], create_fhs=['stdout'])
        result = proc.handles['stdout'].read()
        proc.handles['stdout'].close()
        proc.wait()
        keys = []
        # UID lines
        lines = result.split("\n")
        for line in lines:
            if line.startswith("pub "):
                foo, ktmp = line.split("/", 1)
                k, foo = ktmp.split(" ", 1)
                keys.append(k)
        return keys

    def delete_key(self, keyid):
        """Delete a public key. Note: This doesn't return a status. It either
        succeeds or it errors.  Simples!"""
        # TODO Not tested this yet.
        self.reset_options()
        idlist = [keyid]
        proc = self.gnupg.run(['--delete-key'], args=idlist)
        proc.wait()

    def import_key(self, key, dryrun=False):
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
        proc = self.gnupg.run(['--import'],
                              args=filelist,
                              create_fhs=['logger', 'stdout'])
        result = proc.handles['logger'].read()
        proc.handles['logger'].close()
        proc.handles['stdout'].close()
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
        proc = self.gnupg.run(['--symmetric'],
                              create_fhs=['stdin'],
                              attach_fhs={'stdout': temp})
        proc.handles['stdin'].write(payload)
        proc.handles['stdin'].close()
        proc.wait()
        temp.seek(0)
        ciphertext = temp.read()
        temp.close()
        return ciphertext

    def signcrypt(self, recipient, senderkey, passphrase, payload,
                  throw_key=False):
        temp = tempfile.TemporaryFile()
        recipients = [recipient]
        self.reset_options()
        self.gnupg.options.recipients = recipients
        self.gnupg.options.default_key = senderkey
        self.gnupg.options.extra_args = []
        self.gnupg.options.extra_args.append('--always-trust')
        self.gnupg.options.extra_args.append('--pinentry-mode=loopback')
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
        Status dictionary.

        """
        key = '[0-9A-F]{8}'
        date = '[0-9]{4}-[0-9]{2}-[0-9]{2}'
        keytype = '[0-9]{3,6}[RDg]'

        # gpg: encrypted with 2048-bit ELG-E key, ID F207AEDB,
        # created 2003-06-04
        enc = 'gpg: encrypted with (\d+)-bit'
        enc += ' (\S+) key'
        enc += '.*ID (%s)' % key
        enc += ".*created (%s)$" % date
        enc_re = re.compile(enc)

        # pub   1024D/228761E7 2003-06-04
        gpg_pub = 'pub +(%s)/(%s) (%s)' % (keytype, key, date)
        self.gpg_pub = re.compile(gpg_pub)
        # pub   4096R/1D6A8052 2010-12-13 [expired: 2011-12-13]
        gpg_pub_expired = '%s \[expired: (%s)\]' % (gpg_pub, date)
        self.gpg_pub_expired = re.compile(gpg_pub_expired)
        # pub   4096R/1B0AAE44 2010-12-28 [expires: 2015-12-27]
        gpg_pub_expires = '%s \[expires: (%s)\]' % (gpg_pub, date)
        self.gpg_pub_expires = re.compile(gpg_pub_expires)

        # sub   1024D/228761E7 2003-06-04
        gpg_sub = 'sub +(%s)/(%s) (%s)' % (keytype, key, date)
        self.gpg_sub = re.compile(gpg_sub)
        # sub   4096R/1D6A8052 2010-12-13 [expired: 2011-12-13]
        gpg_sub_expired = '%s \[expired: (%s)\]' % (gpg_sub, date)
        self.gpg_sub_expired = re.compile(gpg_sub_expired)
        # sub   4096R/1B0AAE44 2010-12-28 [expires: 2015-12-27]
        gpg_sub_expires = '%s \[expires: (%s)\]' % (gpg_sub, date)
        self.gpg_sub_expires = re.compile(gpg_sub_expires)

        # gpg: decryption failed: secret key not available
        decfail_re = re.compile("gpg: decryption failed: (.*)")

        # gpg: public key decryption failed: bad passphrase
        pkdfail_re = re.compile("gpg: public key decryption failed: (.*)")

        # gpg: Good signature from "Steven Crook"
        goodsig_re = re.compile("gpg: Good signature from \"(.*)\"")

        # gpg:                 aka "Steven Crook <steve@mixmin.net>"
        akasig_re = re.compile("gpg: +aka \"(.*)\"")

        # gpg: Signature made Sun 10 Jul 2011 12:02:04 BST using DSA key ID
        # 228761E7
        sigmade = "gpg: Signature made (.*) using (.*) key ID ([0-9A-F]+)"
        sigmade_re = re.compile(sigmade)

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
        # gpg: key 50343676: "Flump (Flump Nym) <flump@mixnym.net>" not changed
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
        self.fingerprint_re = fingerprint_re
        self.verifyfail = verifyfail

    def __getitem__(self, key):
        return self.gpgstat[key]

    def __iter__(self):
        return iter(self.gpgstat)

    def __setitem__(self, key, item):
        self.gpgstat[key] = item

    def _strip_gpg(self, text):
        gpg, rest = text.split(": ", 1)
        return rest

    def _epoch_from_datestr(self, datestr):
        """Return epoch seconds when passed a date string formatted as:
        2011-07-11.  GnuPG seems to use this format for key dates.

        """
        return int(time.mktime(time.strptime(datestr, '%Y-%m-%d')))

    def _listdict_append(self, key, value):
        if key in self.gpgstat:
            self.gpgstat[key].append(value)
        else:
            self.gpgstat[key] = [value]

    def statparse(self, status):
        """Take a GnuPG Status message and parse it into specific dictionary
        elements. We might not capture every possible element but at least all
        those we need to perform effective validation.

        """
        # Dictionary of GPG status that external programs will interrogate.
        # First into this is the raw status message that GnuPG returns.
        self.gpgstat = {'status': status}

        # All status lines begin with gpg: but we'll let the regexs take care
        # of that for us.
        lines = status.split("\n")
        lastline = None
        for line in lines:
            # First we'll look for errors as there's no point populating a
            # dict that's not returned.
            # gpg: CRC error; 44FB85 - C2B77E
            if line.startswith("gpg: CRC error"):
                err = self._strip_gpg(line)
                raise GnupgError(err)

            enc_match = self.enc_re.match(line)
            if enc_match:
                self.gpgstat['ekeylen'] = enc_match.group(1)
                self.gpgstat['ekeytype'] = enc_match.group(2)
                self.gpgstat['ekeyid'] = enc_match.group(3)
                encdate = enc_match.group(4)
                self.gpgstat['ekeydate'] = self._epoch_from_datestr(encdate)

            sigmade_match = self.sigmade_re.match(line)
            if sigmade_match:
                # We attempt to convert the signature date to seconds since
                # epoch format.
                sigdate = sigmade_match.group(1)
                sigepoch = email.utils.parsedate(sigdate)
                self.gpgstat['sigdate'] = time.mktime(sigepoch)
                self.gpgstat['sigtype'] = sigmade_match.group(2)
                self.gpgstat['keyid'] = sigmade_match.group(3)

            fingerprint_match = self.fingerprint_re.search(line)
            # Check for lastline prevents picking up the fingerprint for subkey
            # instead of the primary.
            if fingerprint_match and not lastline.startswith("sub"):
                fp = fingerprint_match.group(1)
                self.gpgstat['fingerprint'] = fp.replace(" ", "")

            decfail_match = self.decfail_re.match(line)
            if decfail_match:
                self.gpgstat['decfail'] = True
                self.gpgstat['decfailreason'] = decfail_match.group(1)

            pkdfail_match = self.pkdfail_re.match(line)
            if pkdfail_match:
                self.gpgstat['pkdfail'] = True
                self.gpgstat['pkdfailreason'] = pkdfail_match.group(1)

            goodsig_match = self.goodsig_re.match(line)
            if goodsig_match:
                self.gpgstat['goodsig'] = True
                txt = goodsig_match.group(1)
                if 'uidtext' not in self.gpgstat:
                    self.gpgstat['uidtext'] = []
                self.gpgstat['uidtext'].append(txt)

                # Perform a sub-match on the sig text to see if it contains a
                # valid email address.
                goodsigmail_match = self.email_re.search(txt)
                if goodsigmail_match:
                    if 'uidmail' not in self.gpgstat:
                        self.gpgstat['uidmail'] = []
                    self.gpgstat['uidmail'].append(goodsigmail_match.group(0))

            # AKA lines in key signatures
            akasig_match = self.akasig_re.match(line)
            if akasig_match:
                txt = akasig_match.group(1)
                if 'uidtext' not in self.gpgstat:
                    # This should never happen.  Can't get an aka without first
                    # having processed a signature. Processing that signature
                    # would create the 'uidtext' element.
                    raise GnupgError("Unexpected aka before signature")
                self.gpgstat['uidtext'].append(txt)
                # Perform a sub-match on the sig text to see if it contains a
                # valid email address.
                akasigmail_match = self.email_re.search(txt)
                if akasigmail_match:
                    if 'uidmail' not in self.gpgstat:
                        # This is a valid condition because the Signature line
                        # might contain a non-email uid.
                        self.gpgstat['uidmail'] = []
                    self.gpgstat['uidmail'].append(akasigmail_match.group(0))

            # UID lines
            if line.startswith("uid"):
                foo, uid = line.split(" ", 1)
                uid = uid.strip()
                if 'uidtext' not in self.gpgstat:
                    self.gpgstat['uidtext'] = []
                self.gpgstat['uidtext'].append(uid)
                uidmail_match = self.email_re.search(uid)
                if uidmail_match:
                    if 'uidmail' not in self.gpgstat:
                        self.gpgstat['uidmail'] = []
                    self.gpgstat['uidmail'].append(uidmail_match.group(0))

            # PUB lines
            pub_match = self.gpg_pub.match(line)
            if pub_match:
                pub_expires_match = self.gpg_pub_expires.match(line)
                pub_expired_match = self.gpg_pub_expired.match(line)
                if pub_expires_match:
                    expires = pub_expires_match.group(4)
                    self.gpgstat['expires'] = self._epoch_from_datestr(expires)
                elif pub_expired_match:
                    expired = pub_expired_match.group(4)
                    self.gpgstat['expired'] = self._epoch_from_datestr(expired)
                self.gpgstat['sigtype'] = pub_match.group(1)
                self.gpgstat['keyid'] = pub_match.group(2)
                sigdate = pub_match.group(3)
                self.gpgstat['sigdate'] = self._epoch_from_datestr(sigdate)

            # SUB lines
            sub_match = self.gpg_sub.match(line)
            if sub_match:
                sub_expires_match = self.gpg_sub_expires.match(line)
                sub_expired_match = self.gpg_sub_expired.match(line)
                if sub_expires_match:
                    expires = sub_expires_match.group(4)
                    self._listdict_append('sub_expires',
                                          self._epoch_from_datestr(expires))
                else:
                    # When no match occurs, we need to append something, else
                    # lists of subkeys aren't synced with eachother.
                    self._listdict_append('sub_expires', None)

                if sub_expired_match:
                    expired = sub_expired_match.group(4)
                    self._listdict_append('sub_expired',
                                          self._epoch_from_datestr(expired))
                else:
                    self._listdict_append('sub_expired', None)

                self._listdict_append('sub_sigtype', sub_match.group(1))
                self._listdict_append('sub_keyid', sub_match.group(2))
                sigdate = sub_match.group(3)
                self._listdict_append('sub_sigdate',
                                      self._epoch_from_datestr(sigdate))

            if line == self.nottrusted:
                self.gpgstat['trusted'] = False

            if line.startswith(self.imported):
                foo, numpro = line.split("processed: ")
                self.gpgstat['imported'] = int(numpro)

            # Importing keys
            import_match = self.import_re.match(line)
            import_nc_match = self.import_nc_re.match(line)
            if import_match:
                self.gpgstat['keyid'] = import_match.group(1)
                uid = import_match.group(2)
            if import_nc_match:
                self.gpgstat['keyid'] = import_nc_match.group(1)
                uid = import_nc_match.group(2)
            if import_match or import_nc_match:
                if 'uidtext' not in self.gpgstat:
                    self.gpgstat['uidtext'] = []
                self.gpgstat['uidtext'].append(uid)
                email_match = self.email_re.search(uid)
                if email_match:
                    if 'uidmail' not in self.gpgstat:
                        self.gpgstat['uidmail'] = []
                    self.gpgstat['uidmail'].append(email_match.group(0))

            # Verify Failure
            if line.startswith(self.verifyfail):
                self.gpgstat['goodsig'] = False
            # In some instances, (like fingerprint) we need to check the
            # previous line to get the correct match.
            lastline = line


def main():
    g = GnuPGFunctions()
    gp = GnuPGStatParse()
    for k in g.listkeys():
        gp.statparse(g.keyinfo(k))
        if 'expired' in gp:
            print "%(keyid)s" % gp


# Call main function.
if (__name__ == "__main__"):
    main()
