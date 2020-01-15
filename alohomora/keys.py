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

import os

try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser

import boto3


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
    print("""\n\n----------------------------------------------------------------
Your new access key pair has been stored in the AWS configuration file {0} under the {1} profile.'
To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile {1} ec2 describe-instances).'
----------------------------------------------------------------\n\n""".format(filename, profile))
