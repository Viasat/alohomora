"""Does some work parsing SAML assertions"""

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

import base64

import xml.etree.ElementTree as ET


def get_roles(assertion):
    """Parse the returned assertion and extract the authorized roles"""
    awsroles = []
    root = ET.fromstring(base64.b64decode(assertion))
    for attr in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        if attr.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role':
            for value in attr.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                awsroles.append(value.text)

    # Note the format of the attribute value should be role_arn,principal_arn
    # but lots of blogs list it as principal_arn,role_arn so let's reverse
    # them if needed
    for awsrole in awsroles:
        chunks = awsrole.split(',')
        if 'saml-provider' in chunks[0]:
            newawsrole = chunks[1] + ',' + chunks[0]
            index = awsroles.index(awsrole)
            awsroles.insert(index, newawsrole)
            awsroles.remove(awsrole)

    awsroles.sort()
    return awsroles
