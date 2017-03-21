# Copyright 2017 ViaSat, Inc.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     https://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import alohomora

from setuptools import setup

setup(
    name='alohomora',
    version=alohomora.__version__,
    author=alohomora.__author__,
    author_email='vice@viasat.com',
    packages=['alohomora'],
    scripts=['bin/alohomora'],
    url='https://github.com/ViaSat/alohomora',
    license=alohomora.__license__,
    description="Get AWS API keys for a SAML-federated identity",
    install_requires=[
        "boto3>=1.3.1",
        "beautifulsoup4>=4.5.1",
        "requests>=2.11.1",
    ],
)
