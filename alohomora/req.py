"""The workhorse functions that make web requests."""

# Copyright 2023 Viasat, Inc.

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

import re
import json
import logging
import time
import os
import base64
from http.cookiejar import LWPCookieJar

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

FIDO2_SUPPORT = False
try:
    from fido2.rpid import verify_rp_id
    from fido2.hid import CtapHidDevice
    from fido2.ctap import STATUS
    from fido2.client import Fido2Client, ClientError
    from fido2.utils import websafe_encode, websafe_decode
    FIDO2_SUPPORT = True
except ImportError as err:
    pass


LOG = logging.getLogger('alohomora.req')


def get_wa_devices():
    '''Return all eligible webauthn devices'''
    return sorted(list(CtapHidDevice.list_devices()), key=lambda k: k.product_name, reverse=True)

prompted = set()
def on_keepalive(status):
    '''Print the tap prompt'''
    if status == STATUS.UPNEEDED and 'ok' not in prompted:  # Waiting for touch
        print('Please tap your security key...')
        prompted.add('ok')

if FIDO2_SUPPORT:
    try:
        _fido_devices = get_wa_devices()
        FIDO2_SUPPORT = True
    except: # pylint: disable=bare-except
        FIDO2_SUPPORT = False


class DuoDevice():
    """A Duo authentication device"""
    def __init__(self, requests_thing):
        self.value = requests_thing.get('value').strip()
        self.name = requests_thing.get_text().strip()

    def __repr__(self):
        return "%s/%s" % (self.name, self.value)


class DuoFactor():
    """A Duo device factor"""
    def __init__(self, name):
        self.value = None
        self.name = name

    def __repr__(self):
        return "%s/%s" % (self.name, self.value)


class WebProvider():
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

    def _validate_webauthn_request(self, host, appid):
        LOG.debug('req["appid"]: %s, host: %s', appid, host)
        return appid == f'https://{host}'

    def _get_webauthn_response(self, req):
        """
        Authenticates against yubikey with all the sign requests
        """
        # if webauthn enrolled, requests will look like
        # {
        #   "extensions": {"appId": "https://api-12345678.duosecurity.com"},
        #   "challenge": "shfdsjkaKJDGHFSKgfesgfieo2382",
        #   "allowCredentials": [{
        #     "transports": ["usb", "nfc", "ble"],
        #     "type": "public-key",
        #     "id":
        # "dipB0Q2TgTSpOINIsI9uaesA4ZrI1nGoeKc3Dx-VOvAJ1knOY46MzjY3da14KcTzLPzlIJF9p9gtqr2t6TfWeQ"
        #   }]
        #   "sessionId": "dn6WlN9Uunff3ZLSZuu9bdHTr1Nhj0p7Ov89ZcR77nI",
        #   "userVerification": "discouraged",
        #   "rpId": "duosecurity.com",
        #   "timeout": 60000
        # }

        wa_devices = get_wa_devices()
        if not wa_devices:
            raise IOError('no FIDO2 devices found')
        LOG.info('WebauthN requests: %s', req)
        cred_id = req['allowCredentials'][0]['id']
        session_id = req['sessionId']
        fido_req = dict()
        for k, val in req.items():
            if k in ['challenge', 'timeout', 'rpId', 'allowCredentials',
                    'userVerification', 'extensions']:
                if k == 'challenge':
                    fido_req[k] = websafe_decode(val)
                elif k == 'allowCredentials':
                    fido_req[k] = []
                    for cred in val:
                        i = cred.copy()
                        i['id'] = websafe_decode(i['id'])
                        fido_req[k].append(i)
                else:
                    fido_req[k] = val
        # pass challenge to all devices sequentially
        while len(wa_devices) > 0:
            device = wa_devices.pop(0)
            client = Fido2Client(device, req['extensions']['appid'], verify_rp_id)
            LOG.debug('trying device %s with req %s', client, fido_req)
            try:
                if device not in prompted:
                    print('Please tap your security key...')
                    prompted.add(device)
                wa_resp = client.get_assertion(fido_req, on_keepalive=on_keepalive).get_response(0)
                LOG.debug('wa_resp: %s', wa_resp)
                LOG.debug('wa_resp.client_data: %s', wa_resp.client_data)
                LOG.debug('wa_resp.authenticator_data: %s', wa_resp.authenticator_data)

                def b64enc(buf):
                    return websafe_encode(buf)

                def b64_raw_enc(buf):
                    return base64.b64encode(buf).decode('utf-8').replace('+','-').replace('/','_')

                def hex_encode(buf):
                    return buf.hex()

                ## encode relevant fields, based on the following snippet from duo ##
                r"""
                full message:
                    {"sid":"MGEzMDE3NGFjNmUwNDA1Yzk4MDZkNzdhOTRlODI0NWY=|104.129.198.109|1649389439|84db9f7e589d6ac2e82b135c60d06fa92dca9c75","device":"webauthn_credential","factor":"webauthn_finish","response_data":"{\\"sessionId\\":\\"AoL2xv58zp6_lMiKSobkVYNBoU9ZhlzzlBLb7uQ-VPc\\",\\"id\\":\\"dipB0Q2TgTSpOINIsI9uaesA4ZrI1nGoeKc3Dx-VOvAJ1knOY46MzjY3da14KcTzLPzlIJF9p9gtqr2t6TfWeQ\\",\\"rawId\\":\\"dipB0Q2TgTSpOINIsI9uaesA4ZrI1nGoeKc3Dx-VOvAJ1knOY46MzjY3da14KcTzLPzlIJF9p9gtqr2t6TfWeQ\\",\\"type\\":\\"public-key\\",\\"authenticatorData\\":\\"5Gq7wMECJqSk1hzZqsDdJP5jU8V79HTtuMIpu6_lawUBAAANQA==\\",\\"clientDataJSON\\":\\"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiRnE1QWwxNFZnZng0UUpxRFVHQnBSNWdaQlJDUkhMdnciLCJvcmlnaW4iOiJodHRwczovL2FwaS02OTI2NzkxOC5kdW9zZWN1cml0eS5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2V9\\",\\"signature\\":\\"3046022100af6749afdca444ca389c91143b256d6fa2b3be71f2da8ec71a30661c9cd9524a022100eb5083196d0076bf7235db9a44c846cc56922a5aa3b9c135ad8b34b49aeeae31\\",\\"extensionResults\\":{\\"appid\\":false}}","out_of_date":"","days_out_of_date":"","days_to_block":"None"}
                    parsed response_data:
                    {
                    "sessionId":"AoL2xv58zp6_lMiKSobkVYNBoU9ZhlzzlBLb7uQ-VPc",
                    "id":"dipB0Q2TgTSpOINIsI9uaesA4ZrI1nGoeKc3Dx-VOvAJ1knOY46MzjY3da14KcTzLPzlIJF9p9gtqr2t6TfWeQ",
                    "rawId":"dipB0Q2TgTSpOINIsI9uaesA4ZrI1nGoeKc3Dx-VOvAJ1knOY46MzjY3da14KcTzLPzlIJF9p9gtqr2t6TfWeQ",
                    "type":"public-key",
                    "authenticatorData":"5Gq7wMECJqSk1hzZqsDdJP5jU8V79HTtuMIpu6_lawUBAAANQA==",
                    "clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiRnE1QWwxNFZnZng0UUpxRFVHQnBSNWdaQlJDUkhMdnciLCJvcmlnaW4iOiJodHRwczovL2FwaS02OTI2NzkxOC5kdW9zZWN1cml0eS5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                    "signature":"3046022100af6749afdca444ca389c91143b256d6fa2b3be71f2da8ec71a30661c9cd9524a022100eb5083196d0076bf7235db9a44c846cc56922a5aa3b9c135ad8b34b49aeeae31",
                    "extensionResults":{"appid":false}}

                    https://api-69267918.duosecurity.com/frame/static/js/page/v3/prompt.js?v=73485:formatted

                    exports.b64enc = function(buf) {
                        return base64js.fromByteArray(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "")
                    }
                    ,
                    exports.b64RawEnc = function(buf) {
                        return base64js.fromByteArray(buf).replace(/\+/g, "-").replace(/\//g, "_")
                    }
                    ,
                    exports.hexEncode = function(buf) {
                        return Array.from(buf).map(function(x) {
                            return ("0" + x.toString(16)).substr(-2)
                        }).join("")
                    }
                    _transformAssertionData: function(sid, assertionData, options) {
                        void 0 === options && (options = {});
                        var authenticatorData = new Uint8Array(assertionData.response.authenticatorData)
                          , clientDataJSON = new Uint8Array(assertionData.response.clientDataJSON)
                          , rawId = new Uint8Array(assertionData.rawId)
                          , signature = new Uint8Array(assertionData.response.signature)
                          , wData = {
                            sessionId: assertionData.sessionId,
                            id: assertionData.id,
                            rawId: (0,
                            _b.b64enc)(rawId),
                            type: assertionData.type,
                            authenticatorData: (0,
                            _b.b64RawEnc)(authenticatorData),
                            clientDataJSON: (0,
                            _b.b64RawEnc)(clientDataJSON),
                            signature: (0,
                            _b.hexEncode)(signature),
                            extensionResults: assertionData.extensionResults
                        };
                        return _jquery.extend({
                            sid: sid,
                            device: "webauthn_credential",
                            factor: "webauthn_finish",
                            response_data: JSON.stringify(wData)
                        }, options)
                    sessionId, id, rawId, type, authenticatorData, clientDataJSON, signature, extensionResults
                """

                # signature is hex #
                resp = dict()
                resp['signature'] = hex_encode(wa_resp.signature)

                # authenticatorData is a url-safe base64-encoded blob #
                resp['authenticatorData'] = b64_raw_enc(wa_resp.authenticator_data)

                # clientDataJSON is a base64-encoded JSON blob #
                resp['clientDataJSON'] = b64_raw_enc(wa_resp.client_data)

                # extensionResults needs some massaging #
                resp['extensionResults'] = dict(appid=False)
                raw_id = b64enc(wa_resp.get('credentialId'))
                resp['rawId'] = raw_id
                resp['id'] = cred_id
                resp['sessionId'] = session_id
                resp['type'] = 'public-key'
                return resp

            except ClientError as err:
                if err.code == ClientError.ERR.DEVICE_INELIGIBLE and len(list(wa_devices)) > 0:
                    print('Please try another authenticator')
                    continue
                if err.code == ClientError.ERR.TIMEOUT:
                    # this is a retryable error
                    print('Timeout waiting for tap, please try again')
                    # put it back on the head of the list so it's used again
                    wa_devices.insert(0, device)
                    continue
                # other errors are OTHER_ERROR, BAD_REQUEST, and CONFIGURATION_UNSUPPORTED
                # so we can safely continue on with other devices without any error handling
                LOG.error(err)
                continue
            except KeyboardInterrupt:
                answer = input('Interrupted, would you like to continue? [Y/n] ')
                if answer in ('Y', 'y', ''):
                    continue
                raise
            finally:
                device.close()
        answer = input('No registered WebauthN device found, retry? [Y/n] ')
        if answer in ('Y', 'y', ''):
            return self._get_webauthn_response(req)
        raise RuntimeWarning('No registered WebauthN device found')

    def login_one_factor(self, username, password):
        self.session = requests.Session()
        self.session.cookies = LWPCookieJar(os.path.expanduser('~/.alohomora.cookiejar'))

        (response, soup) = self._do_get(self.idp_url)
        payload = {}

        username_set = False
        password_set = False
        for inputtag in soup.find_all('input'):
            name = inputtag.get('name', '')
            # value = inputtag.get('value', '')
            if "user" in name.lower():
                # Make an educated guess that this is the right field for the username
                payload[name] = username
                username_set = True
            elif "email" in name.lower():
                # Some IdPs also label the username field as 'email'
                payload[name] = username
            elif "pass" in name.lower():
                # Make an educated guess that this is the right field for the password
                LOG.debug('Detected password field, prompting for password')
                payload[name] = password if not callable(password) else password()
                password_set = True
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
        if not username_set:
            assertion = ''
            for inputtag in soup.find_all('input'):
                if inputtag.get('name') == 'SAMLResponse':
                    # print(inputtag.get('value'))
                    assertion = inputtag.get('value')
            if assertion != '':
                return (True, assertion)
            alohomora.die("Couldn't find right form field for username!")
        elif not password_set:
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
        frame_url = (f'https://{duo_host}/frame/web/v1/auth'
                     f'?tx={duo_sig}&parent={response_1fa.url}&v=2.3')
        LOG.info('Getting Duo iframe')
        # if the duo integration has an allowed origin list, we must
        # pass the page URL as a Referer header in addition to using
        # the `parent` query parameter in the frame URL
        origin_duo_host = f'https://{duo_host}'
        (response, soup) = self._do_get(frame_url, headers={
            'Referer': response_1fa.url,
            'Origin': origin_duo_host
        })

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

        do_wa = device.value.startswith('WA')
        # Finally send the POST request for an auth to Duo
        payload = {
            'sid': sid,
            'device': device.value,
            'factor': factor.name,
            'out_of_date': ''
        }
        LOG.debug("Payload: %s", payload)
        if factor.name == "Passcode":
            payload['passcode'] = factor.value
        prompt_sid_url = response.url
        headers = {'Referer': prompt_sid_url,
            'Origin': origin_duo_host}
        if do_wa:
            # pull in the webauthn prompt
            popup_url = (f'https://{duo_host}{new_action}/'
                         f'webauthn_auth_popup?sid={sid}&wkey={device.value}')
            LOG.debug("Popup URL: %s", popup_url)
            (status, soup) = self._do_get(
                popup_url,
                headers=headers)
            payload = {
                'sid': sid,
                'device': device.value,
                'factor': factor.name if (
                    device.name != "Security Key (U2F)"
                    and not device.value.startswith('WA')) else "WebAuthn Credential",
            }
            headers = {'Referer': popup_url, 'Origin': origin_duo_host}

        (status, _) = self._do_post(f'https://{duo_host}{new_action}', data=payload,
            headers=headers, soup=False)

        # Response is of form
        # {"stat": "OK", "response": {"txid": "f95cbacc-151c-43a6-b462-b33420e72633"}}
        LOG.debug("Received response: %s", status.text)
        response = json.loads(status.text)['response']
        txid = response['txid']
        LOG.debug("Received response %s", response)
        LOG.debug("Received transaction ID %s", txid)

        headers = {'Referer': prompt_sid_url, 'Origin': origin_duo_host}
        # Initial call will NOT block
        (status, _) = self._do_post(f'https://{duo_host}/frame/status',
                data={'sid': sid, 'txid': txid}, headers=headers, soup=False)
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
        # if webauthn enrolled, text will be like:
        # {
        #   'stat': 'OK',
        #   'response': {
        #       'status': 'Use your Security Key to log in.',
        #       'status_code': 'webauthn_sent',
        #       'status_body_msg': 'Use your security key to log in.',
        #       'webauthn_credential_request_options': {
        #           'allowCredentials': [{'transports': ['usb', 'nfc', 'ble'],
        #               'type': 'public-key', 'id':
        # 'dipB0Q2TgTSpOINIsI9uaesA4ZrI1nGoeKc3Dx-VOvAJ1knOY46MzjY3da14KcTzLPzlIJF9p9gtqr2t6TfWeQ'
        #           }],
        #           'challenge': 'jUXmEDWAxx7b3jPxu57vGu7xvfWAulE8', 'rpId': 'duosecurity.com',
        #           'timeout': 60000, 'sessionId': 'dn6WlN9Uunff3ZLSZuu9bdHTr1Nhj0p7Ov89ZcR77nI',
        #           'userVerification': 'discouraged', 'extensions': {
        #               'appid': 'https://api-69267918.duosecurity.com'
        #           }
        #       }
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
        if status_data['response']['status_code'] == 'webauthn_sent':
            opts = status_data['response']['webauthn_credential_request_options']
            challenges = [r for r in opts['allowCredentials']
                          if self._validate_webauthn_request(duo_host, opts['extensions']['appid'])]
            if not challenges:
                alohomora.die('Sorry, there was a problem talking to Duo.')
            resp = self._get_webauthn_response(opts)
            LOG.debug(resp)

            # include the session ID as passed to us earlier
            payload['sid'] = sid
            # webauthn_credential and webauthn_finish are magic strings here
            payload['device'] = 'webauthn_credential'
            payload['factor'] = 'webauthn_finish'
            # these are a copy/paste from the duo integration's POST data
            payload['out_of_date'] = None
            payload['days_out_of_date'] = None
            payload['days_to_block'] = 'None'
            # finally, the response data itself needs to be a JSON string
            payload['response_data'] = json.dumps(resp,separators=(',', ':'))

            LOG.debug(payload)

            (status, _) = self._do_post(f'https://{duo_host}{new_action}', data=payload,
                headers=headers, soup=False)
            status_data = json.loads(status.text)
            # Response is of form
            # {"stat": "OK", "response": {"txid": "f95cbacc-151c-43a6-b462-b33420e72633"}}
            txid = json.loads(status.text)['response']['txid']
            LOG.debug("Received transaction ID %s from response %s", txid, status.text)

            # Initial call will NOT block
            (status, _) = self._do_post(f'https://{duo_host}/frame/status',
                data={'sid': sid, 'txid': txid}, headers=headers, soup=False)
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
            (status, _) = self._do_post(f'https://{duo_host}/frame/status',
                data={'sid': sid, 'txid': txid}, soup=False)
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
                f'https://{duo_host}{status_data["response"]["result_url"]}',
                data={'sid': sid}, soup=False)
            postresult_data = json.loads(postresult.text)
            signed_auth = postresult_data['response']['cookie']
        elif 'cookie' in status_data['response']:
            # Leaving this option in here, in case Duo treats different users differently
            signed_auth = status_data['response']['cookie']
        else:
            raise Exception("Unable to find signed token from successful Duo auth")

        payload = {
            '_eventId_proceed': 'transition',
            'sig_response': f'{signed_auth}:{app_sig}'
        }
        (response, soup) = self._do_post(response_1fa.url, data=payload)

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
            FIDO2_SUPPORT and dev.value.startswith('WA'))]

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
            return DuoFactor('webauthn_credential')
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
        try:
            self.session.cookies.load(ignore_discard=True, ignore_expires=True)
        except FileNotFoundError:
            pass
        LOG.debug("Pre cookie jar: %s", self.session.cookies)
        LOG.debug("Fetching from URL: %s", url)
        response = func(url, data=data, headers=headers)
        LOG.debug("Post cookie jar: %s", self.session.cookies)
        LOG.debug("Request headers: %s", response.request.headers)
        LOG.debug("Response headers: %s", response.headers)
        self.session.cookies.save(ignore_discard=True, ignore_expires=True)
        if soup:
            the_soup = BeautifulSoup(response.text, 'html.parser')
        else:
            the_soup = None
        return (response, the_soup)
