#!/usr/bin/env python
# -*- coding:utf-8 -*-

# Copyright 2015 Cisco Systems, Inc.
# All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

""" BGP Route injector
"""

from __future__ import print_function

import random
import sys
import urllib.request
import json
import time

from oslo_config import cfg


CONF = cfg.CONF

CONF.register_cli_opts([
    cfg.StrOpt('peerip', help='The BGP peer address'),
    cfg.IntOpt('interval', default=0, help='time interval when sending message'),
    cfg.IntOpt('count', default=10000, help='the number of messages you want to generate')]
)

rest_server_ops = [
    cfg.StrOpt('host',
               default='0.0.0.0',
               help='Address to bind the API server to'),
    cfg.IntOpt('port',
               default=8801,
               help='Port the bind the API server to'),
    cfg.StrOpt('user',
               default='admin',
               help='Username for api server'),
    cfg.StrOpt('passwd',
               default='admin',
               help='Password for api server',
               secret=True)
]

CONF.register_cli_opts(rest_server_ops, group='rest')


msg_source_ops = [
    cfg.StrOpt('json',
               help='json format update messages'),
    cfg.StrOpt('list',
               help='yabgp raw message file')
]

CONF.register_cli_opts(msg_source_ops, group='message')

bgp_config_ops = [
    cfg.StrOpt('nexthop',
               help='new next hop address'),
    cfg.StrOpt('originator_id',
               help='new originator id'),
    cfg.ListOpt('cluster_list',
                help='new cluster list'
                ),
    cfg.BoolOpt('no_origin_cluster',
                default=True,
                help='remove originator id and cluster list')
]

CONF.register_cli_opts(bgp_config_ops, group='attribute')


URL = 'http://%s:%s/v1/peer/%s/send/update'


def get_api_opener_v1(url, username, password):
    """
    get the http api opener with base url and username,password

    :param url: http url
    :param username: username for api auth
    :param password: password for api auth
    """
    # create a password manager
    password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()

    # Add the username and password.
    password_mgr.add_password(None, url, username, password)

    handler = urllib.request.HTTPBasicAuthHandler(password_mgr)
    opener = urllib.request.build_opener(handler)
    return opener


def get_data_from_agent(url, username, password, method='GET', data=None):
    """
    HTTP interaction with yabgp rest api
    :param url:
    :param username:
    :param password:
    :param method:
    :param data:
    :return:
    :return:
    """
    # build request
    if data:
        data = json.dumps(data).encode('utf-8')
    request = urllib.request.Request(url, data)
    request.add_header("Content-Type", 'application/json')
    request.get_method = lambda: method
    opener_v1 = get_api_opener_v1(url, username, password)
    try:
        res = json.loads(opener_v1.open(request).read())
        return True
    except Exception as e:
        print(e)
        return False


def interval():
    time.sleep(CONF.interval)


def get_random_ipv4_addr():
    mask_randmon = random.randint(16, 32)
    ip_addr = f"{random.getrandbits(8)}.{random.getrandbits(8)}.{random.getrandbits(8)}.{random.getrandbits(8)}"
    return ip_addr + "/" + str(mask_randmon)


def init_ipv4_unicast_template():
    # list_random length < 10
    random_len = random.randint(1, 10)
    random_set = set()
    for _ in range(random_len):
        random_set.add(random.getrandbits(16))

    # community length < 10
    community_len = random.randint(1, 10)
    community_set = set()
    for _ in range(community_len):
        community_set.add(f"{random.getrandbits(16)}:{random.getrandbits(16)}")

    color_random = random.getrandbits(16)

    # nlri length < 20
    nlri_len = random.randint(1, 20)
    nlri_random = set()
    for _ in range(nlri_len):
        nlri_random.add(get_random_ipv4_addr())

    message_json = {
        "type": 2,
        "msg": {
            "attr": {
                "1": 0,
                "2": [[2, list(random_set)]],
                "3": "192.0.2.1",
                "5": 500,
                "8": list(community_set),
                "16": [f"color:{color_random}"]
            },
            "nlri": list(nlri_random)
        }
    }

    return message_json


def send_update():
    url = 'http://{bind_host}:{bind_port}/v1/peer/{peer_ip}/send/update'
    url = url.format(bind_host=CONF.rest.host, bind_port=CONF.rest.port, peer_ip=CONF.peerip)
    message_count = CONF.count
    bar_length = 50
    message_pass_send = 0
    send_success = 0
    send_failed = 0
    current_percent = 0.00
    percent_step = 0.01

    for _ in range(message_count):
        message_json = init_ipv4_unicast_template()
        if message_json['type'] != 2:
            message_count -= 1
            continue
        message = message_json['msg']
        if message['nlri']:
            if CONF.attribute.no_origin_cluster:
                if message['attr'].get('9'):
                    message['attr'].pop('9')
                if message['attr'].get('10'):
                    message['attr'].pop('10')
            elif CONF.attribute.originator_id and CONF.attribute.cluster_list:
                message['attr']['9'] = CONF.attribute.originator_id
                message['attr']['10'] = CONF.attribute.cluster_list
            if CONF.attribute.nexthop:
                message['attr']['3'] = CONF.attribute.nexthop
            post_data = {
                'nlri': message['nlri'],
                'attr': message['attr']
            }
            res = get_data_from_agent(url, 'admin', 'admin', 'POST', post_data)
            if res:
                send_success += 1
                interval()
            else:
                send_failed += 1
            while message_pass_send / message_count >= current_percent / 100:
                hashes = '#' * int(message_pass_send / message_count * bar_length)
                spaces = ' ' * (bar_length - len(hashes))
                sys.stdout.write("\rPercent: [%s] %.2f%%" % (hashes + spaces, current_percent))
                sys.stdout.flush()
                current_percent += percent_step
            message_pass_send += 1
        else:
            # TODO support other address family
            message_count -= 1
            continue
    hashes = '#' * bar_length
    spaces = ''
    sys.stdout.write("\rPercent: [%s] %.2f%%" % (hashes + spaces, 100.00))
    sys.stdout.flush()
    print('\nTotal messages:   %s' % int(message_count))
    print('Success send out: %s' % send_success)
    print('Failed send out:  %s' % send_failed)


if __name__ == '__main__':
    CONF(args=sys.argv[1:])
    try:
        send_update()
    except KeyboardInterrupt:
        sys.exit()
