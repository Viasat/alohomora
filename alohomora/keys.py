"""Handles getting and saving AWS API keys"""

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

import json
import os
from datetime import datetime, timezone

try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser

import boto3

import alohomora

# https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_saml.html#troubleshoot_saml_duration-exceeds
DURATION_MIN = 15*60
DURATION_MAX = 12*60*60


def get(role_arn, principal_arn, assertion, duration):
    """Use the assertion to get an AWS STS token using Assume Role with SAML"""
    # We must use a session with a govcloud region for govcloud accounts
    if role_arn.split(':')[1] == 'aws-us-gov':
        session = boto3.session.Session(region_name='us-gov-west-1')
        client = session.client('sts')
    else:
        client = boto3.client('sts')
    token = client.assume_role_with_saml(
        RoleArn=role_arn,
        PrincipalArn=principal_arn,
        DurationSeconds=(duration),
        SAMLAssertion=assertion)
    return token


def save(token, profile):
    """Write the AWS STS token into the AWS credential file"""

    filename = os.path.expanduser("~/.aws/credentials")

    # Read in the existing config file
    config = ConfigParser.RawConfigParser()
    config.read(filename)

    # This makes sure there is a [default] section if that's where
    # the caller wants to put the profile. Don't ask me why this
    # works when the config.has_section() test below doesn't. Config
    # be strange.
    #
    if profile.lower() == 'default' and 'default' not in config.sections():
        config.add_section('default')

    # Put the credentials into a saml specific section instead of clobbering
    # the default credentials
    if not config.has_section(profile):
        config.add_section(profile)

    config.set(profile, 'aws_access_key_id', token['Credentials']['AccessKeyId'])
    config.set(profile, 'aws_secret_access_key', token['Credentials']['SecretAccessKey'])
    config.set(profile, 'aws_session_token', token['Credentials']['SessionToken'])

    # Write the updated config file
    with open(filename, 'w+') as configfile:
        config.write(configfile)

    # Give the user some basic info as to what has just happened
    alohomora.eprint("""\n\n----------------------------------------------------------------
Your new access key pair has been stored in the AWS configuration file {0} under the {1} profile.'
To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile {1} ec2 describe-instances).'
----------------------------------------------------------------\n\n""".format(filename, profile))


def print_token(token):
    """Print the AWS STS token to STDOUT for use with aws cli credential_process."""
    print(json.dumps({
        "Version": 1,
        "AccessKeyId": token['Credentials']['AccessKeyId'],
        "SecretAccessKey": token['Credentials']['SecretAccessKey'],
        "SessionToken": token['Credentials']['SessionToken'],
        "Expiration": token['Credentials']['Expiration'].isoformat()
    }, indent=4))


def cache(token, alohomora_profile):
    """Write the AWS STS token to a cache file with Expiration Time."""

    filename = os.path.expanduser("~/.alohomora.cache")
    # Read in the existing cache file
    cache = ConfigParser.RawConfigParser()
    try:
        cache.read(filename)
    except ConfigParser.Error:
        alohomora.eprint('Error reading your ~/.alohomora.cache configuration file.')

    # This makes sure there is a [default] section if that's where
    # the caller wants to put the profile. Don't ask me why this
    # works when the cache.has_section() test below doesn't. Config
    # be strange.
    #
    if alohomora_profile.lower() == 'default' and 'default' not in cache.sections():
        cache.add_section('default')

    # Put the credentials into a saml specific section instead of clobbering
    # the default credentials
    if not cache.has_section(alohomora_profile):
        cache.add_section(alohomora_profile)

    cache.set(alohomora_profile, 'aws_access_key_id', token['Credentials']['AccessKeyId'])
    cache.set(alohomora_profile, 'aws_secret_access_key', token['Credentials']['SecretAccessKey'])
    cache.set(alohomora_profile, 'aws_session_token', token['Credentials']['SessionToken'])
    cache.set(alohomora_profile, 'exiration_time', token['Credentials']['Expiration'].isoformat())

    # Write the updated cache file
    with open(filename, 'w+') as cachefile:
        cache.write(cachefile)


def get_cache(alohomora_profile):
    """Read and return non-expired cached credentials."""
    filename = os.path.expanduser("~/.alohomora.cache")
    # Read in the existing cache file
    cache = ConfigParser.RawConfigParser()
    try:
        cache.read(filename)
    except ConfigParser.Error:
        alohomora.eprint('Error reading your ~/.alohomora.cache configuration file.')
        return None

    if not cache.has_section(alohomora_profile):
        return None

    token = {'Credentials': {}}
    token['Credentials']['AccessKeyId'] = cache.get(alohomora_profile, 'aws_access_key_id')
    token['Credentials']['SecretAccessKey'] = cache.get(alohomora_profile, 'aws_secret_access_key')
    token['Credentials']['SessionToken'] = cache.get(alohomora_profile, 'aws_session_token')
    token['Credentials']['Expiration'] = datetime.fromisoformat(cache.get(alohomora_profile, 'exiration_time'))

    if token['Credentials']['Expiration'] > datetime.now(tz=timezone.utc):
        return token

    # Remove cached credentials that are now stale
    cache.remove_section(alohomora_profile)
    # Write the updated cache file
    with open(filename, 'w+') as cachefile:
        cache.write(cachefile)
