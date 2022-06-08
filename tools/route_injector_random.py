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
    cmd: python route_injector_random.py --rest-host={ip} --rest-port={port} --count={count} --afi-safi={afi_safi}
"""

from __future__ import print_function

import ipaddress
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
    cfg.IntOpt('count', default=10000, help='the number of messages you want to generate'),
    cfg.StrOpt('afi-safi',
               default='ipv4_unicast',
               help='the address family of messages you want to generate',
               choices=['ipv4_unicast', 'ipv4_mpls_vpn', 'ipv4_label_unicast', 'ipv6_unicast', 'ipv6_mpls_vpn',
                        'ipv6_label_unicast', 'evpn'])]
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
        return res['status']
    except Exception as e:
        return False


def interval():
    time.sleep(CONF.interval)


def get_random_ip(v):
    """
    :param v: 4: ipv4, 6: ipv6
    """
    if v == 4:
        ipv4 = ipaddress.IPv4Address(random.getrandbits(32))
        return str(ipv4)
    elif v == 6:
        ipv6 = ipaddress.IPv6Address(random.getrandbits(128))
        # .compressed contains the short version of the IPv6 address
        # str(ipv6) always returns the short address
        # .exploded is the opposite of this, always returning the full address with all-zero groups and so on
        return str(ipv6.compressed)


def get_random_ip_mask(v):
    """
    :param v: 4: ipv4, 6: ipv6
    """
    if v == 4:
        return random.randint(16, 32)
    elif v == 6:
        return random.randint(64, 128)


def get_random_list(length=10, random_type=1):
    """
    :param random_type: 1:list, 2:community, 3:ip addr
    """
    tmp_len = random.randint(1, length)
    tmp_set = set()
    if random_type == 1:
        for _ in range(tmp_len):
            tmp_set.add(random.getrandbits(16))
    elif random_type == 2:
        for _ in range(tmp_len):
            tmp_set.add(f"{random.getrandbits(16)}:{random.getrandbits(16)}")
    elif random_type == 3:
        for _ in range(tmp_len):
            tmp_set.add(f"{get_random_ip(4)}/{get_random_ip_mask(4)}")

    return list(tmp_set)


def init_ipv4_unicast_template():
    random_list = get_random_list(10, 1)
    community_list = get_random_list(10, 2)
    color_random = random.getrandbits(16)
    nlri_random_list = get_random_list(20, 3)

    message_json = {
        "attr": {
            "1": 0,
            "2": [[2, random_list]],
            "3": "192.0.2.1",
            "5": 500,
            "8": community_list,
            "16": [f"color:{color_random}"]
        },
        "nlri": nlri_random_list
    }

    return message_json


def init_ipv4_mpls_vpn_template():
    label_list = get_random_list(5, 1)
    rd = f"{random.getrandbits(16)}:{random.getrandbits(16)}"
    color_random = random.getrandbits(16)
    nlri_list_len = 3
    nlri_list = []
    for _ in range(nlri_list_len):
        nlri_list.append({
            "label": label_list,
            "rd": f"{random.getrandbits(16)}:{random.getrandbits(16)}",
            "prefix": f"{get_random_ip(4)}/{get_random_ip_mask(4)}"
        })

    message_json = {
        "attr": {
            "1": 0,
            "2": [],
            "5": 100,
            "14": {
                "afi_safi": [1, 128],
                "nexthop": {"rd": rd, "str": get_random_ip(4)},
                "nlri": nlri_list
            },
            "16": [f"route-target:{random.getrandbits(16)}:{random.getrandbits(16)}", f"color:{color_random}"]
        }
    }

    return message_json


def init_ipv4_label_unicast_template():
    color_random = random.getrandbits(16)
    label_list = get_random_list(5, 1)
    nlri_list_len = 10
    nlri_list = []
    for _ in range(nlri_list_len):
        nlri_list.append({
            "label": label_list,
            "prefix": f"{get_random_ip(4)}/{get_random_ip_mask(4)}"
        })
    message_json = {
        "attr": {
            "1": 0,
            "2": [],
            "5": 400,
            "14": {
                "afi_safi": [1, 4],
                "nexthop": get_random_ip(4),
                "nlri": nlri_list
            },
            "16": [f"color:{color_random}"]
        }
    }

    return message_json


def init_ipv6_unicast_template():
    random_list = get_random_list(10, 1)
    community_list = get_random_list(10, 2)
    nlri_list_len = 3
    nlri_list = []
    for _ in range(nlri_list_len):
        nlri_list.append(f"{get_random_ip(6)}/{get_random_ip_mask(6)}")
    message_json = {
        "attr": {
            "1": 0,
            "2": [[2, random_list]],
            "5": 500,
            "8": community_list,
            "14": {
                "afi_safi": [2, 1],
                "nexthop": get_random_ip(6),
                "nlri": nlri_list
            }
        },
        "nlri": []
    }

    return message_json


def init_ipv6_mpls_vpn_template():
    rd = f"{random.getrandbits(16)}:{random.getrandbits(16)}"
    color_random = random.getrandbits(16)
    label_list = get_random_list(5, 1)
    nlri_list_len = 3
    nlri_list = []
    for _ in range(nlri_list_len):
        nlri_list.append({
            "label": label_list,
            "rd": f"{random.getrandbits(16)}:{random.getrandbits(16)}",
            "prefix": f"{get_random_ip(6)}/{get_random_ip_mask(6)}"
        })

    message_json = {
        "attr": {
            "1": 0,
            "2": [],
            "5": 100,
            "14": {
                "afi_safi": [2, 128],
                "nexthop": {"rd": rd, "str": get_random_ip(6)},
                "nlri": nlri_list
            },
            "16": [f"route-target:{random.getrandbits(16)}:{random.getrandbits(16)}", f"color:{color_random}"]
        }
    }

    return message_json


def init_ipv6_label_unicast_template():
    label_list = get_random_list(5, 1)
    nlri_list_len = 3
    nlri_list = []
    for _ in range(nlri_list_len):
        nlri_list.append({
            "label": label_list,
            "prefix": f"{get_random_ip(6)}/{get_random_ip_mask(6)}"
        })
    message_json = {
        "attr": {
            "1": 0,
            "2": [],
            "5": 400,
            "14": {
                "afi_safi": [2, 4],
                "nexthop": get_random_ip(6),
                "nlri": nlri_list
            }
        }
    }

    return message_json


def init_evpn_template():
    rd = f"{get_random_ip(4)}:{random.getrandbits(16)}"
    mac_list = [0x58, 0x96, 0x1D, random.getrandbits(8), random.getrandbits(8), random.getrandbits(8)]
    mac = '-'.join(map(lambda x: "%02x" % x, mac_list))
    message_json = {
        "attr": {
            "1": 0,
            "2": [],
            "5": 100,
            "14": {
                "afi_safi": [25, 70],
                "nexthop": get_random_ip(4),
                "nlri": [
                    {
                        "type": 2,
                        "value": {
                            "eth_tag_id": 108,
                            "ip": get_random_ip(4),
                            "label": [0],
                            "rd": rd,
                            "mac": mac,
                            "esi": 0
                        }
                    }
                ]
            },
            "16": ["mac-mobility:1:500"]
        }
    }

    return message_json


MSG_TYPE_DICT = {
    'ipv4_unicast': init_ipv4_unicast_template,
    'ipv4_mpls_vpn': init_ipv4_mpls_vpn_template,
    'ipv4_label_unicast': init_ipv4_label_unicast_template,
    'ipv6_unicast': init_ipv6_unicast_template,
    'ipv6_mpls_vpn': init_ipv6_mpls_vpn_template,
    'ipv6_label_unicast': init_ipv6_label_unicast_template,
    'evpn': init_evpn_template,
}


def send_update():
    url = 'http://{bind_host}:{bind_port}/v1/peer/{peer_ip}/send/update'
    url = url.format(bind_host=CONF.rest.host, bind_port=CONF.rest.port, peer_ip=CONF.peerip)
    message_count = CONF.count
    message_type = CONF.afi_safi
    bar_length = 50
    message_pass_send = 0
    send_success = 0
    send_failed = 0
    current_percent = 0.00
    percent_step = 0.01

    for _ in range(message_count):
        message = MSG_TYPE_DICT[message_type]()
        res = get_data_from_agent(url, 'admin', 'admin', 'POST', message)
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
