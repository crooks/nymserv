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

from email.mime.application import MIMEApplication
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.parser import Parser
from urllib2 import Request, urlopen, URLError
from httplib import InvalidURL
import logging
import email.utils
import strutils
from Config import config


class Error(Exception):
    """Base class for exceptions in this module."""
    pass


class DirectiveError(Error):
    """User supplied directives are incompatible."""
    def __init__(self, expr):
        self.expr = expr

    def __str__(self):
        return repr(self.expr)


class URL():
    def __init__(self):
        # This URL checks for an acceptable format of config line.
        self.handled_mime_types = ['text', 'application', 'image']
        user_agent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'
        self.headers = {'User-Agent': user_agent}
        self.maxsize = config.get('thresholds', 'url_size_limit')
        self.fromhdr = 'url@' + config.get('domains', 'default')
        # Ths default domain name (only used in the From header).

    def main(self, payload):
        urls, key, hsubhash = self.extract_directives(payload)
        return self.fetch_and_prep(urls)

    def extract_directives(self, payload):
        # These three variables store the required keys from within a URL
        # request.
        urls = []
        key = None
        hsubhash = None
        # Parse each line of the received and decrypted message.
        for line in payload.split('\n'):
            opt, val = strutils.optparse(line)
            if opt == "source" or opt == "url":
                if not val in urls:
                    if not val.startswith("http://"):
                        val = "http://%s" % val
                    urls.append(val)
            if opt == "key":
                key = val
            if opt == "hsub":
                hsubhash = val
        if len(urls) == 0:
            raise DirectiveError("No URLs defined in directives.")
        if key is None:
            raise DirectiveError("No Symmetric encryption key in directives.")
        if hsubhash is None:
            # Where no directive is provided for hSub, we set it to the
            # provided Symmetric key value.
            hsubhash = key
        return urls, key, hsubhash

    def fetch_and_prep(self, urls):
        # Set up the basics of our multipart MIME response.
        url_msg = MIMEMultipart('alternative')
        url_msg['From'] = self.fromhdr
        url_msg['To'] = 'somebody@alt.anonymous.messages'
        url_msg['Subject'] = 'Nym Retrieval'
        url_msg['Date'] = email.utils.formatdate()
        for url in urls:
            # ct is Content-Type header.
            try:
                message, ct = self.geturl(url)
                logging.info("Retrieved %s" % url)
            except URLError, e:
                if hasattr(e, 'reason'):
                    message = "Could not fetch %s. Got: %s" % (url, e.reason)
                    ct = 'text/plain'
                elif hasattr(e, 'code'):
                    message = "Could not fetch %s: %d error" % (url, e.code)
                    ct = 'text/plain'
            except InvalidURL, e:
                message = "Invalid URL: %s. Reason: %s" % (url, e)
                ct = 'text/plain'
            if len(message) > self.maxsize:
                msglen = len(message)
                message = "Could not fetch %s: Size of %s " % (url, msglen)
                message += "exceeds configured limit of %s" % self.maxsize
                ct = 'text/plain'

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
            if not type in self.handled_mime_types:
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
        return mime_msg

    def geturl(self, url):
        req = Request(url, None, self.headers)
        f = urlopen(req)
        # Try and obtain the Content-Type of the URL
        info = f.info()
        if 'Content-Type' in info:
            ct = info['Content-Type']
        else:
            ct = None
        return f.read(), ct
