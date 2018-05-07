"""Alohomora helper module"""

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

from __future__ import print_function

import sys

try:
    input = raw_input
except NameError:
    pass

__version__ = '1.2.1'
__author__ = 'Stephan Kemper'
__license__ = '(c) 2017 ViaSat, Inc. See the LICENSE file for more details.'


def die(msg):
    """Exit with non-zero and a message"""
    print(msg)
    sys.exit(5)


def _prompt_for_a_thing(msg, arr, func=lambda x: x, allow_interactive=None):
    """Given a list of items, ask the user to pick one"""
    if allow_interactive == None:
        raise Exception(
            "_prompt_for_a_thing missing require arugment: allow_interactive")
    elif not allow_interactive:
        print("Prompt requested:", repr(msg))
        die("However, refusing to prompt in non-interactive mode")
    print(msg)
    i = 0
    for thing in arr:
        print('[ %d ] %s' % (i, func(thing)))
        i += 1
    thing_index = _prompt_index(arr)
    while thing_index is None:
        print('You have entered an invalid ID')
        thing_index = _prompt_index(arr)
    return arr[thing_index]


def _prompt_index(arr):
    try:
        device_index = int(input('ID: '))
    except ValueError:
        return None
    if not 0 <= device_index <= (len(arr) - 1):
        return None
    else:
        return device_index
