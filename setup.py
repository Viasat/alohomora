# Copyright 2020 ViaSat, Inc.

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
    author_email=alohomora.__author_email__,
    license=alohomora.__license__,
    url=alohomora.__url__,
    description=alohomora.__description__,

    packages=['alohomora'],
    entry_points={
        "console_scripts": [
            "alohomora=alohomora.main:main",
        ],
    },
    install_requires=[
        "boto3>=1.3.1",
        "beautifulsoup4>=4.5.1",
        "requests>=2.11.1",
    ],
    extras_require={
        "u2f": ["python-u2flib-host>=3.0.3"]
    }
)
