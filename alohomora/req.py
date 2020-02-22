"""The workhorse functions that make web requests."""

# Copyright 2020 Viasat, Inc.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     https://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# pylint: disable=too-few-public-methods,too-many-branches,too-many-locals,too-many-statements
from __future__ import print_function

import re
import json
import logging
import time
import os

try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse

try:
    from urllib import unquote
except ImportError:
    from urllib.parse import unquote

import requests
from bs4 import BeautifulSoup

import alohomora

U2F_SUPPORT = False
try:
    from u2flib_host import u2f, exc
    from u2flib_host.constants import APDU_USE_NOT_SATISFIED, APDU_WRONG_DATA
    U2F_SUPPORT = True
except ImportError:
    pass

try:
    input = raw_input #pylint: disable=redefined-builtin,invalid-name
except NameError:
    pass


LOG = logging.getLogger('alohomora.req')


def get_u2f_devices():
    """Get all U2F devices attached to the machine"""
    devices = u2f.list_devices()
    for device in devices:
        try:
            device.open()
        except: # pylint: disable=bare-except
            devices.remove(device)
    return devices


if U2F_SUPPORT:
    try:
        get_u2f_devices()
        U2F_SUPPORT = True
    except: # pylint: disable=bare-except
        U2F_SUPPORT = False


class DuoDevice(object):
    """A Duo authentication device"""
    def __init__(self, requests_thing):
        self.value = requests_thing.get('value').strip()
        self.name = requests_thing.get_text().strip()

    def __repr__(self):
        return "%s/%s" % (self.name, self.value)


class DuoFactor(object):
    """A Duo device factor"""
    def __init__(self, name):
        self.value = None
        self.name = name

    def __repr__(self):
        return "%s/%s" % (self.name, self.value)


class WebProvider(object):
    """A provider of authentication data from some web source"""
    def login_one_factor(self, username, password):
        """Authenticates the user to the IDP with a primary factor (username and password)"""
        raise NotImplementedError()

    def login_two_factor(self, response_1fa, auth_device=None):
        """Authenticates the user with a second factor"""
        raise NotImplementedError()



class DuoRequestsProvider(WebProvider):
    """A requests-based provider of authentication data"""
    #pylint: disable=too-many-arguments,no-self-use,logging-not-lazy
    def __init__(self, idp_url, auth_method=None):
        self.session = None
        self.idp_url = idp_url
        self.auth_method = auth_method

    def _validate_u2f_request(self, host, req):
        LOG.debug('req["appId"]: %s, host: %s', req['appId'], host)
        return req['appId'] == 'https://%s' % host

    def _get_u2f_response(self, reqs):
        """
        Authenticates against yubikey with all the sign requests
        """
        # if U2F enrolled, requests will look like
        # [
        #   {
        #     "appId": "https://api-12345678.duosecurity.com",
        #     "challenge": "shfdsjkaKJDGHFSKgfesgfieo2382",
        #     "keyHandle": "fjdskabghpferwuipgt4iuytr23g4uyiawhbiu",
        #     "sessionId": "jrt43uiq9tpgh43qu9gbhw3juipgtbw3",
        #     "version": "U2F_V2"
        #   },
        #   { ... }
        # ]
        _ = input('Please ensure your security key is plugged in and hit enter...')
        devices = get_u2f_devices()
        if not devices:
            raise IOError('no U2F devices found')
        LOG.info('U2F requests: %s', reqs)
        try:
            prompted = False
            valid_pairs = []
            removed = []
            # enumerate valid pairs of device: request
            for device in devices:
                LOG.debug('trying device %s', device)
                remove = True
                for request in reqs:
                    try:
                        return u2f.authenticate(device, json.dumps(request), request['appId'])
                    except exc.APDUError as e: #pylint: disable=invalid-name
                        if e.code == APDU_USE_NOT_SATISFIED:
                            valid_pairs.append({'device': device, 'request': request})
                            LOG.debug('device %s just needs a little push', device)
                            remove = False
                            if not prompted:
                                print('Please tap your security key...')
                                prompted = True
                        elif e.code == APDU_WRONG_DATA:
                            LOG.debug('device/request mismatch')
                        else:
                            LOG.error('device %s has other problems: %s', device, e)
                    except exc.DeviceError:
                        LOG.error('DeviceError')
                if remove:
                    LOG.debug('removing device %s', device)
                    removed.append(device)
            for dev in removed:
                dev.close()
            time.sleep(0.5)
            # now loop only over the valid pairs
            while valid_pairs:
                for pair in valid_pairs:
                    device, request = pair['device'], pair['request']
                    try:
                        return u2f.authenticate(device, json.dumps(request), request['appId'])
                    except exc.APDUError as e: #pylint: disable=invalid-name
                        if e.code == APDU_USE_NOT_SATISFIED:
                            # can't imagine getting here, but I'll leave it in
                            if not prompted:
                                print('Please tap your security key...')
                                prompted = True
                        elif e.code == APDU_WRONG_DATA:
                            LOG.debug('device/request mismatch')
                            valid_pairs.remove(pair)
                        else:
                            LOG.error('device %s has other problems: %s', device, e)
                    time.sleep(0.25)
        finally:
            for device in devices:
                device.close()
        answer = input('No registered U2F device found, retry? [Y/n]')
        if answer in ('Y', 'y', ''):
            return self._get_u2f_response(reqs)
        raise RuntimeWarning('No registered U2F device found')

    def login_one_factor(self, username, password):
        self.session = requests.Session()

        (response, soup) = self._do_get(self.idp_url)
        payload = {}

        for inputtag in soup.find_all('input'):
            name = inputtag.get('name', '')
            # value = inputtag.get('value', '')
            if "user" in name.lower():
                # Make an educated guess that this is the right field for the username
                payload[name] = username
            elif "email" in name.lower():
                # Some IdPs also label the username field as 'email'
                payload[name] = username
            elif "pass" in name.lower():
                # Make an educated guess that this is the right field for the password
                payload[name] = password
            else:
                # Populate the parameter with the existing value (picks up hidden fields as well)
                # payload[name] = value
                pass
        payload['_eventId_proceed'] = ''
        # Omit the password from the debug output...
        payload_debugger = {}
        for key in payload:
            if "pass" in key.lower():
                payload_debugger[key] = '****'
            else:
                payload_debugger[key] = payload[key]
        LOG.debug(payload_debugger)
        if username not in payload.values():
            alohomora.die("Couldn't find right form field for username!")
        elif password not in payload.values():
            alohomora.die("Couldn't find right form field for password!")

        # Some IdPs don't explicitly set a form action, but if one is set we should
        # build the idpauthformsubmiturl by combining the scheme and hostname
        # from the entry url with the form action target
        # If the action tag doesn't exist, we just stick with the
        # idpauthformsubmiturl above
        for inputtag in soup.find_all(re.compile('form', re.IGNORECASE)):
            action = inputtag.get('action')
            if action:
                parsedurl = urlparse.urlparse(self.idp_url)
                idpauthformsubmiturl = parsedurl.scheme + "://" + parsedurl.netloc + action

        post_headers = {
            'Referer': response.url,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        (response, soup) = self._do_post(idpauthformsubmiturl, data=payload, headers=post_headers)

        # We need to check if the user actually got logged in
        # See if we have anything classed 'form-error'
        for tag in soup.find_all(lambda x: x.has_attr('class') and 'form-error' in x['class']):
            alohomora.die(tag.get_text())

        # Look for the SAMLResponse attribute of the input tag (determined by
        # analyzing the debug print lines above)
        assertion = ''
        for inputtag in soup.find_all('input'):
            if inputtag.get('name') == 'SAMLResponse':
                # print(inputtag.get('value'))
                assertion = inputtag.get('value')
        if assertion != '':
            return (True, assertion)
        return (False, response)

    def login_two_factor(self, response_1fa, auth_device=None):
        """Log in with the second factor, borrowing first factor data if necessary"""

        soup_1fa = BeautifulSoup(response_1fa.text, 'html.parser')
        duo_host = None
        sig_request = None
        # post_action = None
        for iframe in soup_1fa.find_all('iframe'):
            duo_host = iframe.get('data-host')
            sig_request = iframe.get('data-sig-request')

        sigs = sig_request.split(':')
        duo_sig = sigs[0]
        app_sig = sigs[1]

        # Pulling the iframe into the page
        frame_url = 'https://%s/frame/web/v1/auth?tx=%s&parent=%s&v=2.3' % \
            (duo_host, duo_sig, response_1fa.url)
        LOG.info('Getting Duo iframe')
        (response, soup) = self._do_get(frame_url)

        payload = {}
        for inputtag in soup.find_all('input'):
            name = inputtag.get('name', '')
            value = inputtag.get('value', '')
            # Populate all parameters with the existing value (picks up hidden fields too)
            payload[name] = value

        # Post data to emulate the plugin determination
        LOG.info('Posting plugin information to Duo')
        (response, soup) = self._do_post(frame_url, data=payload)

        sid = unquote(urlparse.urlparse(response.request.url).query[4:])
        new_action = self._get_form_action(soup)
        device = self._get_duo_device(soup, auth_device)
        factor = self._get_auth_factor(soup, device)

        # Finally send the POST request for an auth to Duo
        payload = {
            'sid': sid,
            'device': device.value if (
                device.name != "Security Key (U2F)"
                and not device.value.startswith('WA')) else "u2f_token",
            'factor': factor.name if (
                device.name != "Security Key (U2F)"
                and not device.value.startswith('WA')) else "U2F Token",
            'out_of_date': ''
        }
        if factor.name == "Passcode":
            payload['passcode'] = factor.value
        headers = {'Referer': response.url}
        (status, _) = self._do_post(
            'https://%s%s' % (duo_host, new_action),
            data=payload,
            headers=headers,
            soup=False)

        # Response is of form
        # {"stat": "OK", "response": {"txid": "f95cbacc-151c-43a6-b462-b33420e72633"}}
        txid = json.loads(status.text)['response']['txid']
        LOG.debug("Received transaction ID %s", txid)

        # Initial call will NOT block
        (status, _) = self._do_post(
            'https://%s/frame/status' % duo_host,
            data={'sid': sid, 'txid': txid},
            soup=False)
        # text from this will be something like
        # {
        #   "stat": "OK",
        #   "response": {
        #       "status_code": "pushed",
        #       "status": "Pushed a login request to your device..."
        #   }
        # }
        # if U2F enrolled, text from this will be something like
        # {
        #   "stat": "OK",
        #   "response": {
        #       "status_code": "u2f_sent",
        #       "status": "Use your Security Key to log in.",
        #       "u2f_sign_request": [{"keyHandle": "..."}, {...}]
        #   }
        # }
        status_data = json.loads(status.text)
        LOG.info(str(status_data))
        if status_data['stat'] != 'OK':
            LOG.error("Returned from inital status call: %s", status.text)
            alohomora.die("Sorry, there was a problem talking to Duo.")
        print(status_data['response']['status'])
        allowed = status_data['response']['status_code'] == 'allow'

        # there should never be a case where `allowed` is True if the user picked Security Key
        if device.name == "Security Key (U2F)" or device.value.startswith('WA'):
            challenges = [r for r in status_data['response']['u2f_sign_request']
                          if self._validate_u2f_request(duo_host, r)]
            resp = self._get_u2f_response(challenges)
            # pull the first challenge's sessionId since they all match
            # the challenges list should not be empty here, as the device would not be presented
            # to the user without a corresponding challenge
            resp['sessionId'] = challenges[0]['sessionId']
            # include the session ID as passed to us earlier
            payload['sid'] = sid
            # u2f_token and u2f_finish are magic strings here
            payload['device'] = 'u2f_token'
            payload['factor'] = 'u2f_finish'
            # these are a copy/paste from the duo integration's POST data
            payload['out_of_date'] = None
            payload['days_to_block'] = 'None'
            # finally, the response data itself needs to be a JSON string
            payload['response_data'] = json.dumps(resp)

            (status, _) = self._do_post(
                'https://%s%s' % (duo_host, new_action),
                data=payload,
                headers=headers,
                soup=False)
            status_data = json.loads(status.text)
            # Response is of form
            # {"stat": "OK", "response": {"txid": "f95cbacc-151c-43a6-b462-b33420e72633"}}
            txid = json.loads(status.text)['response']['txid']
            LOG.debug("Received transaction ID %s", txid)

            # Initial call will NOT block
            (status, _) = self._do_post(
                'https://%s/frame/status' % duo_host,
                data={'sid': sid, 'txid': txid},
                soup=False)
            status_data = json.loads(status.text)
            LOG.info(str(status_data))
            if status_data['stat'] != 'OK':
                LOG.error("Returned from inital status call: %s", status.text)
                alohomora.die("Sorry, there was a problem talking to Duo.")
            print(status_data['response']['status'])
            allowed = status_data['response']['status_code'] == 'allow'
            if not allowed:
                alohomora.die("Sorry, there was a problem with your security key, try again.")

        while not allowed:
            # call again to get status of request
            # for a push notification, this will hang until the user approves/denies
            # for a phone call, you need to keep polling until the user approves/denies
            (status, _) = self._do_post(
                'https://%s/frame/status' % duo_host,
                data={'sid': sid, 'txid': txid},
                soup=False)
            status_data = json.loads(status.text)

            if status_data['stat'] != 'OK':
                LOG.error("Returned from second status call: %s", status.text)
                alohomora.die("Sorry, there was a problem talking to Duo.")
            if status_data['response']['status_code'] == 'allow':
                LOG.info("Login allowed!")
                allowed = True
            elif status_data['response']['status_code'] == 'deny':
                LOG.error("Login disallowed: %s", status.text)
                alohomora.die("The login was blocked!")
            else:
                LOG.info("Still waiting... (%s)", status_data['response']['status_code'])
                LOG.debug(str(status_data))
                time.sleep(2)

        signed_auth = ''
        if 'result_url' in status_data['response']:
            # We have to specifically ask Duo for the signed auth string;
            # this doesn't come for free anymore
            (postresult, _) = self._do_post(
                'https://%s%s' % (duo_host, status_data['response']['result_url']),
                data={'sid': sid},
                soup=False
            )
            postresult_data = json.loads(postresult.text)
            signed_auth = postresult_data['response']['cookie']
        elif 'cookie' in status_data['response']:
            # Leaving this option in here, in case Duo treats different users differently
            signed_auth = status_data['response']['cookie']
        else:
            raise Exception("Unable to find signed token from successful Duo auth")

        payload = {
            '_eventId_proceed': 'transition',
            'sig_response': '%s:%s' % (signed_auth, app_sig)
        }
        (response, soup) = self._do_post(
            response_1fa.url,
            data=payload)

        assertion = self._get_assertion(soup)
        return (True, assertion)

        # IdP does a redirect to AWS, a POST with form field SAMLResponse filled out
        # We DON'T want to follow the redirect.  Need to take the SAMLResponse and repurpose

    def _get_form_action(self, soup):
        LOG.debug('Looking for the form action')
        form = soup.find('form')
        if form is None:
            alohomora.die(
                'Expected form not found, please make sure Duo is set up properly.'
                '{}Please check: {}'
                .format(os.linesep, self.idp_url))
        LOG.debug('Found form action %s', form['action'])
        return form['action']

    def _get_duo_device(self, soup, auth_device): #pylint: disable=no-self-use
        """Decide which device to use. Choose <auth_device> if it was specified.
           Otherwise, if there's more than one, ask the user."""
        LOG.debug('Looking for available auth devices')
        for tag in soup.find_all('select'):
            if tag['name'] == 'device':
                devices = []
                for dev in tag.find_all('option'):
                    devices.append(DuoDevice(dev))
                break

        LOG.debug("Available devices: %s" % devices)
        # Only show devices Alohomora can work with
        supported_devices = ['phone', 'phone1', 'phone2', 'token', 'token1', 'token2']
        # allow Security Keys by "name" not by "value", as value is a unique ID
        devices = [dev for dev in devices if dev.value in supported_devices or (
            U2F_SUPPORT and (dev.name == 'Security Key (U2F)' or dev.value.startswith('WA')))]
        u2f_in_devices = False
        # and now to offer a single "Security Key (U2F)" option, since we try all of them
        deduped_devices = []
        for dev in devices:
            if dev.name == 'Security Key (U2F)':
                if u2f_in_devices:
                    continue
                u2f_in_devices = True
            deduped_devices.append(dev)
        devices = deduped_devices

        LOG.debug("Acceptable devices: %s" % devices)

        if auth_device:
            device = next(
                (dev for dev in devices
                 if auth_device.lower() == dev.name.lower()),
                None)

            if not device:
                print('No such auth device: {}'.format(auth_device))

                if len(devices) == 1:
                    print('Using the only device you have: {}'.format(devices[0].name))

        if not auth_device or not device:
            if len(devices) > 1:
                device = alohomora._prompt_for_a_thing( #pylint: disable=protected-access
                    'Please select the device you want to authenticate with:',
                    devices,
                    lambda x: x.name
                )
            else:
                device = devices[0]
        if device.name == 'Security Key (U2F)':
            device.value = 'u2f_token'
        LOG.debug('Returning auth device %s', device)
        return device

    def _get_auth_factor(self, soup, device): #pylint: disable=inconsistent-return-statements
        LOG.debug('Looking up auth factor options for %s', device.value)
        if device.name == 'Security Key (U2F)' or device.value.startswith('WA'):
            return DuoFactor('u2f_factor')
        for tag in soup.find_all('fieldset'):
            if tag.get('data-device-index') == device.value:
                factors = []
                for options in tag.find_all('input'):
                    if options['name'] == 'factor':
                        factors.append(options['value'])
                LOG.debug("Available factors: %s", factors)

                if self.auth_method:
                    tmp_factors = [
                        factor for factor in factors if self.auth_method in factor.lower()]
                    # ignore config if user selects Token but config has different auth_method
                    if tmp_factors:
                        factors = tmp_factors

                if len(factors) > 1:
                    factor_name = alohomora._prompt_for_a_thing( #pylint: disable=protected-access
                        'Please select an authentication method',
                        factors)

                    factor = DuoFactor(factor_name)
                else:
                    factor = DuoFactor(factors[0])

                if factor.name == "Passcode":
                    factor.value = input('Hardware token passcode: ')

                LOG.debug("Returning factor %s", factor)
                return factor

    def _get_assertion(self, soup):
        LOG.debug('Pulling out SAML assertion')
        form = soup.find('form')
        input_tag = form.find('input')
        LOG.debug('Found assertion %s', input_tag['value'])
        return input_tag['value']

    def _do_get(self, url, data=None, headers=None, soup=True):
        return self._make_request(url, self.session.get, data, headers, soup)

    def _do_post(self, url, data=None, headers=None, soup=True):
        return self._make_request(url, self.session.post, data, headers, soup)

    def _make_request(self, url, func, data=None, headers=None, soup=True):
        LOG.debug("Pre cookie jar: %s", self.session.cookies)
        LOG.debug("Fetching from URL: %s", url)
        response = func(url, data=data, headers=headers)
        LOG.debug("Post cookie jar: %s", self.session.cookies)
        LOG.debug("Request headers: %s", response.request.headers)
        LOG.debug("Response headers: %s", response.headers)
        if soup:
            the_soup = BeautifulSoup(response.text, 'html.parser')
        else:
            the_soup = None
        return (response, the_soup)
