'''
alohomora console script
'''

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

from __future__ import print_function

import argparse
import getpass
import logging
import os
import re
import sys

try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser


import alohomora
import alohomora.keys
from alohomora.keys import DURATION_MIN, DURATION_MAX
import alohomora.req
import alohomora.saml

DEFAULT_AWS_PROFILE = 'saml'
DEFAULT_ALOHOMORA_PROFILE = 'default'
DEFAULT_IDP_NAME = 'sso'

#
# Set up logging
#
logging.basicConfig(filename=os.path.expanduser('~/.alohomora.log'),
                    level=logging.WARN,
                    format='%(asctime)-15s %(levelname)-5s %(name)s %(message)s')
logging.getLogger('botocore').setLevel(logging.WARN)
logging.getLogger('boto3').setLevel(logging.WARN)
logging.getLogger('requests').setLevel(logging.DEBUG)
LOG = logging.getLogger('alohomora')


def to_seconds(tstr):
    """Takes string in form of 3h/25m/13s/13 and returns integer seconds.
    No unit specified implies seconds."""
    try:
        val, suffix = re.match("^([0-9]+)([HhMmSs]?)$", tstr).groups()
    except:
        alohomora.die("Can't parse duration '%s'" % tstr)
    scale = {'h': 3600, 'm': 60}.get(suffix.lower(), 1)

    return int(val) * scale


def format_role(role_arn, account_map):
    # arn:aws:iam::{{ accountid }}:role/{{ role_name }}
    account_id = role_arn.split(':')[4]
    account_name = account_map.get(account_id)
    if account_name:
        role_name = role_arn.split("/")[-1]
        return account_name + ": " + role_name + " - " + role_arn
    else:
        return role_arn


class Main(object):
    """Actually does stuff."""

    def __init__(self):
        #
        # We don't specify actual defaults here, so that we can try and load
        # them from the config file later on.  Using None signals that the
        # user didn't provide a value, and it's safe to look farther down the
        # precedence tree.
        #
        parser = argparse.ArgumentParser()
        parser.add_argument("--username",
                            help="Username to login as",
                            default=None)
        parser.add_argument("--idp-url",
                            help="The entry point for your SAML Identity Provider",
                            default=None)
        parser.add_argument("--aws-profile",
                            help="Save AWS credentials to specified profile",
                            default=None)
        parser.add_argument("--duration",
                            help="Request AWS token with specified duration in seconds "
                                 "(min: {}, max: {})".format(DURATION_MIN, DURATION_MAX),
                            default=None)
        parser.add_argument("--account",
                            help="AWS account number you want to access",
                            default=None)
        parser.add_argument("--role-name",
                            help="Name of the role you want to assume",
                            default=None)
        parser.add_argument("--auth-device",
                            help="Which Duo device you want to use for authentication",
                            default=None)
        parser.add_argument("--auth-method",
                            help="How you want Duo to authenticate you",
                            default=None)
        parser.add_argument("--idp-name",
                            help="Name of your SAML IdP, as registered with AWS",
                            default=None)
        parser.add_argument("--aws-partition",
                            help="Partition of AWS you're using, e.g. `aws-us-gov`",
                            default=None)
        parser.add_argument("--alohomora-profile",
                            help="Name of the alohomora profile to use",
                            default=DEFAULT_ALOHOMORA_PROFILE)
        parser.add_argument("--debug",
                            action='store_true',
                            help="Set the log level to debug",
                            default=False)
        parser.add_argument("--version",
                            action='store_true',
                            help="Print the program version and exit",
                            default=False)
        self.options = parser.parse_args()

        # if debug is passed, set log level to DEBUG
        if self.options.debug:
            logging.getLogger("alohomora").setLevel(logging.DEBUG)

        #
        # config file
        #
        filename = os.path.expanduser("~/.alohomora")
        try:
            self.config = ConfigParser.RawConfigParser()
            self.config.read(filename)
        except ConfigParser.Error:
            print('Error reading your ~/.alohomora configuration file.')
            raise

    def main(self):
        """Run the program."""

        if self.options.version:
            print('Version:', alohomora.__version__)
            print('Python: ', sys.version.replace('\n', ' ').replace('\r', ''))
            print('README: ', alohomora.__url__)
            return

        # Validate options
        duration = to_seconds(self._get_config('duration', '1h'))

        if not DURATION_MIN <= duration <= DURATION_MAX:
            alohomora.die("Duration of '%s' not in the range of %s-%s seconds" %
                          (self._get_config('duration', None),
                           DURATION_MIN,
                           DURATION_MAX))

        #
        # Get the user's credentials
        #
        username = self._get_config('username', os.getenv("USER"))
        if not username:
            alohomora.die("Oops, don't forget to provide a username")

        password = getpass.getpass()

        idp_url = self._get_config('idp-url', None)
        if not idp_url:
            alohomora.die("Oops, don't forget to provide an idp-url")

        auth_method = self._get_config('auth-method', None)
        auth_device = self._get_config('auth-device', None)

        #
        # Authenticate the user
        #
        provider = alohomora.req.DuoRequestsProvider(idp_url, auth_method)
        (okay, response) = provider.login_one_factor(username, password)
        assertion = None

        if not okay:
            # we need to 2FA
            LOG.info('We need to two-factor')
            (okay, response) = provider.login_two_factor(response, auth_device)
            if not okay:
                alohomora.die('Error doing two-factor, sorry.')
            assertion = response
        else:
            LOG.info('One-factor OK')
            assertion = response

        awsroles = alohomora.saml.get_roles(assertion)

        # If I have more than one role, ask the user which one they want,
        # otherwise just proceed
        if len(awsroles) == 0:
            print('You are not authorized for any AWS roles.')
            sys.exit(0)
        elif len(awsroles) == 1:
            role_arn = awsroles[0].split(',')[0]
            principal_arn = awsroles[0].split(',')[1]
        elif len(awsroles) > 1:
            # arn:{{ partition }}:iam::{{ accountid }}:role/{{ role_name }}
            account_id = self._get_config('account', None)
            role_name = self._get_config('role-name', None)
            idp_name = self._get_config('idp-name', DEFAULT_IDP_NAME)

            # If the user has specified a partition, use it; otherwise, try autodiscovery
            partition = self._get_config('aws-partition', None)
            if partition is None:
                partition = awsroles[0].split(':')[1]

            if account_id is not None and role_name is not None and idp_name is not None:
                role_arn = "arn:%s:iam::%s:role/%s" % (partition, account_id, role_name)
                principal_arn = "arn:%s:iam::%s:saml-provider/%s" % (partition, account_id, idp_name)
            else:
                account_map = {}
                try:
                    accounts = self.config.options('account_map')
                    for account in accounts:
                        account_map[account] = self.config.get('account_map', account)
                except Exception:
                    pass
                selectedrole = alohomora._prompt_for_a_thing(
                    "Please choose the role you would like to assume:",
                    awsroles,
                    lambda s: format_role(s.split(',')[0], account_map))

                role_arn = selectedrole.split(',')[0]
                principal_arn = selectedrole.split(',')[1]

        token = alohomora.keys.get(role_arn, principal_arn, assertion, duration)
        alohomora.keys.save(token, profile=self._get_config('aws-profile', DEFAULT_AWS_PROFILE))

    def __get_alohomora_profile_name(self):
        """
        Get the name of the alohomora configuration profile
        """
        return getattr(self.options, 'alohomora_profile')

    def _get_config(self, name, default):
        cli_name = name.replace('-', '_')
        if hasattr(self.options, cli_name) and getattr(self.options, cli_name) is not None:
            data = getattr(self.options, cli_name)
            LOG.debug("%s is %s from command line", name, data)
            return data

        try:
            data = self.config.get(self.__get_alohomora_profile_name(), name)
            LOG.debug("%s is %s from config file", name, data)
            return data
        except ConfigParser.NoOptionError:
            pass
        except ConfigParser.Error:
            print('Error reading your ~/.alohomora configuration file. The file is either missing or improperly formatted.')
            raise

        data = default
        LOG.debug("%s is %s from default", name, data)
        return data


def main():
    ''' do it
    '''
    Main().main()


if __name__ == '__main__':
    Main().main()
