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
from datetime import datetime, timedelta
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

                ## encode relevant fields ##

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

    def _get_duo_plugin_payload(self, soup, post_url, auth_device):
        ''' Get the DUO plugin payload '''
        payload = { inputtag.get('name', ''): inputtag.get('value', '')
                 for inputtag in soup.find_all('input') }

        xsrf = payload.get('_xsrf', '')

        # Post data to emulate the plugin determination
        (response, soup) = self._do_post(post_url, data=payload)

        sid = unquote(urlparse.urlparse(response.request.url).query[4:])
        new_action = self._get_form_action(soup)
        device = self._get_duo_device(soup, auth_device)
        factor = self._get_auth_factor(soup, device)

        do_wa = device.value.startswith('WA')
        plugin_payload = {
            'sid': sid,
            'device': device.value,
            'factor': factor.name,
            'out_of_date': ''
        }

        if factor.name == "Passcode":
            plugin_payload['passcode'] = factor.value

        if do_wa:
            # configure webauthn plugin info
            plugin_payload['factor'] = factor.name if (
                device.name != "Security Key (U2F)"
                and not device.value.startswith('WA')) else "WebAuthn Credential"

        return (plugin_payload, xsrf, new_action)

    def _wait_for_duo_status(self, allowed, duo_status_endpoint, sid, txid):
        ''' Poll Duo for MFA status '''
        while not allowed:
            # call again to get status of request
            # for a push notification, this will hang until the user approves/denies
            # for a phone call, you need to keep polling until the user approves/denies
            (status, _) = self._do_post(duo_status_endpoint,
                data={'sid': sid, 'txid': txid}, soup=False)
            status_data = json.loads(status.text)

            if status_data['stat'] != 'OK':
                LOG.error(f"Returned from second status call: {status.text}")
                alohomora.die("Sorry, there was a problem talking to Duo.")
            if status_data['response']['status_code'] == 'allow':
                LOG.info("Login allowed!")
                allowed = True
            elif status_data['response']['status_code'] == 'deny':
                LOG.error(f"Login disallowed: {status.text}")
                alohomora.die("The login was blocked!")
            else:
                print(f"Still waiting... ({status_data['response']['status_code']})")
                LOG.info(f"Still waiting... ({status_data['response']['status_code']})")
                LOG.debug(str(status_data))
                time.sleep(2)

        return status_data

    def _process_webauthn_request(self, status_data, plugin_payload, duo_host, sid, iframe=False):
        ''' Wait for webauthn device to be approved '''
        if not iframe:
            duo_prompt_endpoint = f'https://{duo_host}/frame/v4/prompt'
            duo_status_endpoint = f'https://{duo_host}/frame/v4/status'
        else:
            duo_prompt_endpoint = f'https://{duo_host}/frame/prompt'
            duo_status_endpoint = f'https://{duo_host}/frame/status'
        opts = status_data['response']['webauthn_credential_request_options']
        challenges = [r for r in opts['allowCredentials']
                      if self._validate_webauthn_request(duo_host, opts['extensions']['appid'])]
        if not challenges:
            alohomora.die('Sorry, there was a problem talking to Duo.')
        resp = self._get_webauthn_response(opts)
        LOG.debug(resp)

        # include the session ID as passed to us earlier
        plugin_payload['sid'] = sid
        # webauthn_credential and webauthn_finish are magic strings here
        plugin_payload['device'] = 'webauthn_credential'
        plugin_payload['factor'] = 'webauthn_finish'
        # these are a copy/paste from the duo integration's POST data
        plugin_payload['out_of_date'] = None
        plugin_payload['days_out_of_date'] = None
        plugin_payload['days_to_block'] = 'None'
        # finally, the response data itself needs to be a JSON string
        plugin_payload['response_data'] = json.dumps(resp,separators=(',', ':'))

        LOG.debug(plugin_payload)

        (status, _) = self._do_post(duo_prompt_endpoint, data=plugin_payload,
            soup=False)
        status_data = json.loads(status.text)
        # Response is of form
        # {"stat": "OK", "response": {"txid": "f95cbacc-151c-43a6-b462-b33420e72633"}}
        txid = json.loads(status.text)['response']['txid']
        LOG.debug("Received transaction ID %s from response %s", txid, status.text)

        # Initial call will NOT block
        (status, _) = self._do_post(duo_status_endpoint,
            data={'sid': sid, 'txid': txid}, soup=False)
        status_data = json.loads(status.text)
        LOG.info(str(status_data))
        if status_data['stat'] != 'OK':
            LOG.error("Returned from inital status call: %s", status.text)
            alohomora.die("Sorry, there was a problem talking to Duo.")
        allowed = status_data['response']['status_code'] == 'allow'
        if not allowed:
            alohomora.die("Sorry, there was a problem with your security key, try again.")

        factor_name = 'webauthn_finish'
        return (factor_name, txid, allowed, status_data)

    def login_two_factor(self, response_1fa, auth_device=None):
        """Log in with the second factor, borrowing first factor data if necessary"""
        url = response_1fa.url
        parsed = urlparse.urlparse(url)
        path_parts = parsed.path.strip('/').split('/')
        query_params = dict(urlparse.parse_qsl(parsed.query))

        if parsed.netloc.endswith('duosecurity.com'):
            # Detect new Duo Prompt (React SPA at /prompt/{account_id}?authkey=...)
            # vs old Universal Prompt (form-based at /frame/v4/...)
            if (len(path_parts) >= 2 and path_parts[0] == 'prompt'
                    and 'authkey' in query_params):
                LOG.debug("Using new DUO prompt (React SPA)")
                return self._login_two_factor_duo_new_prompt(response_1fa, auth_device)
            else:
                LOG.debug("Using DUO universal prompt")
                return self._login_two_factor_duo_univ(response_1fa, auth_device)
        else:
            LOG.debug("Using DUO iframe prompt")
            return self._login_two_factor_iframe(response_1fa, auth_device)

    def _extract_factor_options(self, factors):
        """Convert raw factors list from pre_authn/evaluation into a flat list of options.

        Returns a list of dicts, each with keys:
          factor_type  – 'push', 'phone_call', 'mobile_otp', 'hardtoken', 'bypass_code'
          pkey         – device key required by auth endpoints (may be None)
          name         – human-readable label including method type (e.g. "iPhone (Push)")
          device_name  – raw device name without method suffix (for --auth-device matching)
        """
        options = []
        for factor in factors:
            ft = factor.get('factor_type', '')
            if ft == 'push':
                di = factor.get('device_info') or {}
                device_name = di.get('name') or di.get('endOfNumber') or 'Duo Push'
                options.append({'factor_type': 'push', 'pkey': di.get('pkey'),
                                 'name': f'{device_name} (Push)', 'device_name': device_name})
            elif ft == 'phone_call':
                pi = factor.get('phone_info') or {}
                device_name = pi.get('name') or pi.get('endOfNumber') or 'Phone'
                options.append({'factor_type': 'phone_call', 'pkey': pi.get('pkey'),
                                 'name': f'{device_name} (Call)', 'device_name': device_name})
            elif ft in ('mobile_otp', 'hardtoken', 'bypass_code'):
                di = factor.get('device_info') or {}
                device_name = di.get('name') or ft
                label = {'mobile_otp': 'Mobile OTP', 'hardtoken': 'Hardware Token',
                         'bypass_code': 'Bypass Code'}.get(ft, ft)
                options.append({'factor_type': ft, 'pkey': di.get('pkey'),
                                 'name': f'{device_name} ({label})', 'device_name': device_name})
        return options

    def _get_factor_type_and_pkey(self, eval_response, auth_device=None):
        """Select a factor type and its pkey from the pre_authn/evaluation response.

        Respects --auth-method (factor type preference) and --auth-device (device
        name matching).  When multiple candidates remain, prompts the user.

        Returns (factor_type, pkey).
        """
        raw_factors = []
        aaf = eval_response.get('available_unified_auth_factors') or {}
        if isinstance(aaf, dict):
            raw_factors = aaf.get('factors', [])
        elif isinstance(aaf, list):
            raw_factors = aaf

        LOG.debug('Available factors from evaluation: %s', raw_factors)
        options = self._extract_factor_options(raw_factors)
        LOG.debug('Parsed factor options: %s', options)

        if not options:
            LOG.warning('No factor options found in evaluation response, falling back to push')
            return ('push', None)

        # Filter by auth_method if specified
        if self.auth_method:
            method = self.auth_method.lower()
            if 'push' in method:
                filtered = [o for o in options if o['factor_type'] == 'push']
            elif 'call' in method or 'phone' in method:
                filtered = [o for o in options if o['factor_type'] == 'phone_call']
            elif 'passcode' in method or 'token' in method or 'otp' in method:
                filtered = [o for o in options
                            if o['factor_type'] in ('mobile_otp', 'hardtoken', 'bypass_code')]
            else:
                filtered = options
            if filtered:
                options = filtered

        # Filter by auth_device name if specified
        if auth_device:
            matched = [o for o in options
                       if auth_device.lower() in o['device_name'].lower()
                       or auth_device.lower() in o['name'].lower()]
            if matched:
                options = matched
            else:
                print(f'No auth device matching "{auth_device}" found; '
                      f'available: {[o["name"] for o in options]}')

        # If still multiple options, prompt the user to choose
        if len(options) > 1:
            chosen = alohomora._prompt_for_a_thing(  # pylint: disable=protected-access
                'Please select the device you want to authenticate with:',
                options,
                lambda o: o['name']
            )
        else:
            chosen = options[0]

        LOG.debug('Selected factor option: %s', chosen)
        return (chosen['factor_type'], chosen['pkey'])

    def _login_two_factor_duo_new_prompt(self, response_1fa, auth_device=None):
        """Handle the new Duo Prompt (React SPA) authentication flow.

        Duo changed from a form-based prompt (/frame/v4/...) to a React SPA
        (/prompt/{account_id}?authkey=...) with a pure REST API backend.

        Flow (derived from duo-auth.js source):
          GET  /prompt/{id}/auth/payload?authkey=...&browser_features=...
          GET  /prompt/{id}/pre_authn/initialization?authkey=...&is_ipad=...&client_hints=...
          GET  /prompt/{id}/pre_authn/evaluation?authkey=...&browser_features=...&local_trust_choice=...
          POST /prompt/{id}/auth/factors/push/auth        {authkey, pkey, otp_code}
          GET  /prompt/{id}/auth/factors/push/status?authkey=...&push_txid=...&saw_good_news=false
            (poll until response.result.status_enum != 13)
          GET  /prompt/{id}/auth/finalize_auth?authkey=...
            → returns response.url (the OIDC exit URL)
          GET  <exit_url>  → follows redirects back to IdP → AWS SAML page
        """
        # AUTH_SUCCESS_MSG=5, AUTH_DENY_MSG=6, AUTH_PUSHED_MSG=13 (still waiting)
        AUTH_SUCCESS = 5
        AUTH_DENY = 6
        AUTH_PUSHED_WAITING = 13

        url = response_1fa.url
        parsed = urlparse.urlparse(url)
        path_parts = parsed.path.strip('/').split('/')
        query_params = dict(urlparse.parse_qsl(parsed.query))

        duo_host = parsed.netloc
        account_id = path_parts[1]
        authkey = query_params['authkey']

        LOG.debug('New Duo prompt: host=%s account_id=%s', duo_host, account_id)
        base_url = f'https://{duo_host}/prompt/{account_id}'

        # browser_features: advertise no WebAuthn so Duo defaults to push/TOTP.
        # Keys match what urlEncodeCollectedBrowserFeatures() in duo-auth.js produces.
        browser_features = json.dumps({
            "touch_supported": False,
            "platform_authenticator_status": "unavailable",
            "webauthn_supported": False,
            "screen_resolution_height": 1080,
            "screen_resolution_width": 1920,
            "screen_color_depth": 24,
            "is_uvpa_available": False,
            "client_capabilities_uvpa": False,
        }, separators=(',', ':'))
        bf_enc = urlparse.quote(browser_features, safe='')

        # client_hints: b64EncodeClientHints(clientHints) = btoa(JSON.stringify(clientHints))
        client_hints_json = json.dumps({"brands": [], "mobile": False}, separators=(',', ':'))
        client_hints = urlparse.quote(
            base64.b64encode(client_hints_json.encode()).decode(), safe='')

        # Step 1: auth/payload — browser fingerprinting, must be called first.
        payload_url = f'{base_url}/auth/payload?authkey={authkey}&browser_features={bf_enc}'
        (resp, _) = self._do_get(payload_url, soup=False)
        LOG.debug('auth/payload status=%s body=%s', resp.status_code, resp.text)
        if json.loads(resp.text).get('stat') != 'OK':
            LOG.warning('auth/payload returned non-OK: %s', resp.text)

        # Step 2: pre_authn/initialization — sets up server-side auth session.
        pre_init_url = (f'{base_url}/pre_authn/initialization'
                        f'?authkey={authkey}&is_ipad=false&client_hints={client_hints}')
        (resp, _) = self._do_get(pre_init_url, soup=False)
        LOG.debug('pre_authn/initialization status=%s body=%s', resp.status_code, resp.text)
        if json.loads(resp.text).get('stat') != 'OK':
            LOG.warning('pre_authn/initialization returned non-OK: %s', resp.text)

        # Step 3: pre_authn/evaluation — returns available auth factors with pkeys.
        eval_url = (f'{base_url}/pre_authn/evaluation'
                    f'?authkey={authkey}&browser_features={bf_enc}&local_trust_choice=undecided')
        (resp, _) = self._do_get(eval_url, soup=False)
        LOG.debug('pre_authn/evaluation status=%s body=%s', resp.status_code, resp.text)
        eval_data = json.loads(resp.text)
        if eval_data.get('stat') != 'OK':
            alohomora.die(f'Duo pre-authn evaluation failed: {resp.text}')

        eval_response = eval_data.get('response', {})
        (factor_type, pkey) = self._get_factor_type_and_pkey(eval_response, auth_device)
        LOG.info('Selected factor_type=%s pkey=%s', factor_type, pkey)

        # Step 4: Initiate the chosen factor and poll for completion.
        if factor_type == 'push':
            # POST /auth/factors/push/auth → {push_txid, ...}
            push_body = {'authkey': authkey, 'otp_code': ''}
            if pkey:
                push_body['pkey'] = pkey
            (resp, _) = self._do_post(
                f'{base_url}/auth/factors/push/auth',
                data=json.dumps(push_body),
                headers={'Content-Type': 'application/json'},
                soup=False)
            LOG.debug('push/auth status=%s body=%s', resp.status_code, resp.text)
            push_data = json.loads(resp.text)
            if push_data.get('stat') != 'OK':
                alohomora.die(f'Duo push initiation failed: {resp.text}')
            push_txid = push_data['response'].get('push_txid', '')
            LOG.debug('push_txid=%s', push_txid)

            # Poll /auth/factors/push/status until success or deny
            saw_good_news = 'false'
            print('Duo Push sent, waiting for approval...')
            while True:
                time.sleep(2)
                status_url = (f'{base_url}/auth/factors/push/status'
                              f'?authkey={authkey}&push_txid={push_txid}'
                              f'&saw_good_news={saw_good_news}')
                (resp, _) = self._do_get(status_url, soup=False)
                LOG.debug('push/status body=%s', resp.text)
                status_data = json.loads(resp.text)
                if status_data.get('stat') != 'OK':
                    alohomora.die(f'Duo push status check failed: {resp.text}')
                status_enum = (status_data.get('response', {})
                               .get('result', {}).get('status_enum'))
                LOG.debug('push status_enum=%s', status_enum)
                if status_enum == AUTH_SUCCESS:
                    print('Duo Push approved!')
                    break
                if status_enum == AUTH_DENY:
                    alohomora.die('Duo Push was denied.')
                if status_enum is None:
                    # Some responses may not have result.status_enum — treat as success
                    LOG.warning('push/status missing status_enum, assuming success: %s', resp.text)
                    break
                if status_enum == AUTH_PUSHED_WAITING:
                    saw_good_news = 'true'  # already showed the "pushed" message
                    print(f'Still waiting for Duo Push approval...')

        elif factor_type == 'phone_call':
            # POST /auth/factors/phone_call → {txid, ...}
            phone_body = {'authkey': authkey}
            if pkey:
                phone_body['pkey'] = pkey
            (resp, _) = self._do_post(
                f'{base_url}/auth/factors/phone_call',
                data=json.dumps(phone_body),
                headers={'Content-Type': 'application/json'},
                soup=False)
            LOG.debug('phone_call status=%s body=%s', resp.status_code, resp.text)
            phone_data = json.loads(resp.text)
            if phone_data.get('stat') != 'OK':
                alohomora.die(f'Duo phone call initiation failed: {resp.text}')
            txid = phone_data['response'].get('txid', '')
            LOG.debug('phone txid=%s', txid)

            # Poll /auth/factors/phone_call/poll until SUCCESS
            print('Duo phone call initiated, waiting for answer...')
            while True:
                time.sleep(2)
                poll_url = (f'{base_url}/auth/factors/phone_call/poll'
                            f'?authkey={authkey}&txid={txid}')
                (resp, _) = self._do_get(poll_url, soup=False)
                LOG.debug('phone_call/poll body=%s', resp.text)
                poll_data = json.loads(resp.text)
                if poll_data.get('stat') != 'OK':
                    alohomora.die(f'Duo phone call poll failed: {resp.text}')
                result = poll_data.get('response', {}).get('result', '')
                LOG.debug('phone_call poll result=%s', result)
                if result == 'SUCCESS':
                    print('Duo phone call approved!')
                    break
                if result == 'STATUS':
                    print(f'Still waiting for phone call...')
                elif result:
                    alohomora.die(f'Duo phone call failed: {resp.text}')

        else:
            # Passcode / OTP
            passcode = input('Hardware token / OTP passcode: ')
            otp_body = {'authkey': authkey}
            if pkey:
                otp_body['pkey'] = pkey
            # Try mobile_otp endpoint; falls back to hardtoken if mobile_otp 404s
            endpoint = f'{base_url}/auth/factors/mobile_otp'
            otp_body['mobile_otp'] = passcode
            (resp, _) = self._do_post(
                endpoint,
                data=json.dumps(otp_body),
                headers={'Content-Type': 'application/json'},
                soup=False)
            LOG.debug('mobile_otp status=%s body=%s', resp.status_code, resp.text)
            otp_data = json.loads(resp.text)
            if otp_data.get('stat') != 'OK':
                # Try hardtoken endpoint
                otp_body2 = {'authkey': authkey, 'hardtoken_code': passcode}
                if pkey:
                    otp_body2['pkey'] = pkey
                (resp, _) = self._do_post(
                    f'{base_url}/auth/factors/hardtoken',
                    data=json.dumps(otp_body2),
                    headers={'Content-Type': 'application/json'},
                    soup=False)
                LOG.debug('hardtoken status=%s body=%s', resp.status_code, resp.text)
                otp_data = json.loads(resp.text)
                if otp_data.get('stat') != 'OK':
                    alohomora.die(f'Duo OTP authentication failed: {resp.text}')

        # Step 5: Finalize — server returns the OIDC exit URL.
        finalize_url = f'{base_url}/auth/finalize_auth?authkey={authkey}'
        (resp, _) = self._do_get(finalize_url, soup=False)
        LOG.debug('finalize_auth status=%s body=%s', resp.status_code, resp.text)
        finalize_data = json.loads(resp.text)
        if finalize_data.get('stat') != 'OK':
            alohomora.die(f'Duo finalize_auth failed: {resp.text}')

        exit_url = finalize_data.get('response', {}).get('url')
        if not exit_url:
            alohomora.die(
                f'No exit URL in Duo finalize_auth response: {resp.text}'
                f'\nCheck ~/.alohomora.log (run with --debug for detail).')

        if exit_url.startswith('/'):
            exit_url = f'https://{duo_host}{exit_url}'

        # Step 6: Follow OIDC exit → IdP callback → AWS SAML page.
        (response, soup) = self._do_get(exit_url)
        assertion = self._get_assertion(soup)
        return (True, assertion)

    def _login_two_factor_duo_univ(self, response_1fa, auth_device=None):
        """Log in with the second factor, borrowing first factor data if necessary"""
        soup = BeautifulSoup(response_1fa.content, 'html.parser')
        post_url = response_1fa.url
        duo_host = urlparse.urlparse(post_url).netloc

        (plugin_payload, xsrf, _) = self._get_duo_plugin_payload(soup, post_url, auth_device)

        sid = plugin_payload['sid']
        factor_name = plugin_payload['factor']

        # Start the Duo Auth request
        (status, _) = self._do_post(f'https://{duo_host}/frame/v4/prompt',
            data=plugin_payload,
            soup=False)

        # Response is of form
        # {"stat": "OK", "response": {"txid": "f95cbacc-151c-43a6-b462-b33420e72633"}}
        response = json.loads(status.text)['response']
        txid = response['txid']

        LOG.debug("Received response: %s", status.text)
        LOG.debug("Received response %s", response)
        LOG.debug("Received transaction ID %s", txid)

        # Initial call will NOT block
        (status, _) = self._do_post(f'https://{duo_host}/frame/v4/status',
                data={'sid': sid, 'txid': txid}, soup=False)

        status_data = json.loads(status.text)
        if status_data['stat'] != 'OK':
            LOG.error("Returned from inital status call: %s", status.text)
            alohomora.die("Sorry, there was a problem talking to Duo.")
        allowed = status_data['response']['status_code'] == 'allow'

        # If not immediately approved, poll for status
        if not allowed:
            # there should never be a case where `allowed` is True if the user picked Security Key
            if status_data['response']['status_code'] == 'webauthn_sent':
                (factor_name, txid, allowed, _) = self._process_webauthn_request(
                    status_data,
                    plugin_payload,
                    duo_host,
                    sid)
            else:
                self._wait_for_duo_status(allowed,
                    f'https://{duo_host}/frame/v4/status',
                    sid,
                    txid)

        payload = {
            "sid": sid,
            "txid": txid,
            "factor": factor_name,
            "device_key": "",
            "_xsrf": xsrf,
            "dampen_choice": False,
        }

        duo_exit_url = f'https://{duo_host}/frame/v4/oidc/exit'

        (response, soup) = self._do_post(duo_exit_url,
            data=payload, soup=True)

        assertion = self._get_assertion(soup)
        return (True, assertion)

    def _login_two_factor_iframe(self, response_1fa, auth_device=None):
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

        (payload, _, new_action) = self._get_duo_plugin_payload(soup, frame_url, auth_device)

        (status, _) = self._do_post(f'https://{duo_host}{new_action}', data=payload,
            soup=False)

        # Response is of form
        # {"stat": "OK", "response": {"txid": "f95cbacc-151c-43a6-b462-b33420e72633"}}
        LOG.debug("Received response: %s", status.text)
        response = json.loads(status.text)['response']
        txid = response['txid']
        sid = payload['sid']
        LOG.debug("Received response %s", response)
        LOG.debug("Received transaction ID %s", txid)

        # Initial call will NOT block
        (status, _) = self._do_post(f'https://{duo_host}/frame/status',
                data={'sid': sid, 'txid': txid}, soup=False)

        status_data = json.loads(status.text)
        LOG.info(str(status_data))
        if status_data['stat'] != 'OK':
            LOG.error("Returned from inital status call: %s", status.text)
            alohomora.die("Sorry, there was a problem talking to Duo.")
        print(status_data['response']['status'])
        allowed = status_data['response']['status_code'] == 'allow'

        # If not immediately approved, poll for status
        if not allowed:
            # there should never be a case where `allowed` is True if the user picked Security Key
            if status_data['response']['status_code'] == 'webauthn_sent':
                (factor_name, txid, allowed, status_data) = self._process_webauthn_request(
                    status_data,
                    payload,
                    duo_host,
                    sid,
                    iframe=True)
            else:
                status_data = self._wait_for_duo_status(
                    allowed,
                    f'https://{duo_host}/frame/status',
                    sid,
                    txid)

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
        # On Windows the python builtin cookiejar chokes on a returned timestamp
        # in the DUO status cookie.  It is set to expire far in the future in the
        # year 9999.  Windows can not parse this timestamp, so we overwite it with
        # an expiration 30 days in the future so it is parsable in Windows.
        future_ts = (datetime.now() + timedelta(days=30)).timestamp()
        for cookie in self.session.cookies:
            if cookie.expires and cookie.expires > future_ts:
                LOG.debug(f"rewrite coookie expires from: {cookie.expires} to: {future_ts}")
                cookie.expires = future_ts
        self.session.cookies.save(ignore_discard=True, ignore_expires=True)
        if soup:
            the_soup = BeautifulSoup(response.text, 'html.parser')
        else:
            the_soup = None
        return (response, the_soup)
