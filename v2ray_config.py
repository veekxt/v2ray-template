import copy
import json
import random
import string
import uuid
from collections import OrderedDict

trans_protocol = ["tcp", "kcp", "ws", "http", "quic"]
data_protocol = ["vmess", "shadowsocks", "socks", "mtproto"]
in_protocol = ["socks", "http"]
use_tls = ["none", "tls"]

config_from_t = {
    "trans_protocol": 4,
    "tls": 1,
    "data_protocol": 3,
    "in": [{"route": 0, "type": 0, "port": 1080}, {"route": 1, "type": 1, "port": 1081},
           {"route": 0, "type": 0, "port": 1083}, {"route": 1, "type": 1, "port": 1084}],
    "server": "veekxt.com",
    "tls_server": "whoami.com",
    "server_port": 443,
    "reversed_proxy": 1,
    "ws_path": "/veekxtwstest",
    "tls_file": "/pa/to/tls",
    "tls_key": "/pa/to/tls/key",
    "extra_mtproto": 1
}


def get_v2ray_config(config_from):
    js_c = None
    js_s = None
    conf_reversed = None
    use_c = True
    use_s = True
    use_re = False

    server_name = ""
    if len(config_from["tls_server"]) > 0:
        server_name = config_from["tls_server"]
    else:
        server_name = config_from["server"]

    v2ray_config_c = OrderedDict([
        ("log", {}),
        #        ("api", {}),
        ("dns", {}),
        ("stats", {}),
        ("inbounds", []),
        ("outbounds", []),
        ("routing", {}),
        ("policy", {}),
        ("reverse", {}),
        ("transport", {}),
    ])

    v2ray_config_s = OrderedDict([
        ("log", {}),
        #        ("api", {}),
        ("dns", {}),
        ("stats", {}),
        ("inbounds", []),
        ("outbounds", []),
        ("routing", {}),
        ("policy", {}),
        ("reverse", {}),
        ("transport", {}),
    ])

    config_from["server_port"] = int(config_from["server_port"])
    local_port = 44222

    inbounds = v2ray_config_c["inbounds"]
    outbounds = v2ray_config_c["outbounds"]
    routing = v2ray_config_c["routing"]

    for i in config_from["in"]:
        if i:
            inbound = {
                "port": i["port"],
                "protocol": in_protocol[i["type"]],
                "settings": {},
                "tag": "in-" + str(len(inbounds)),
            }
            if inbound["protocol"] == "socks":
                inbound["settings"] = {
                    "auth": "noauth",
                    "udp": True
                }
            elif inbound["protocol"] == "http":
                inbound["settings"] = {}
            else:
                print("no that protocol:" + str(inbound["protocol"]))
            inbounds.append(inbound)

    outbound = {
        "protocol": data_protocol[config_from["data_protocol"]],
        "settings": {},
        "tag": "out-" + str(len(outbounds)),
        "streamSettings": {
            "network": trans_protocol[config_from["trans_protocol"]],
            "security": use_tls[config_from["tls"]],
        }
    }

    stream = outbound["streamSettings"]
    network = stream["network"]
    out_set = outbound["settings"]

    data_ps = data_protocol[config_from["data_protocol"]]

    vmess_uuid = str(uuid.uuid4())
    ss_passwd = rand_string(string.ascii_lowercase, 16)

    if data_ps == "vmess":
        out_set["vnext"] = [
            {
                "address": config_from["server"],
                "port": config_from["server_port"],
                "users": [
                    {
                        "id": vmess_uuid,
                        "alterId": 32,
                    }
                ]
            }
        ]
    elif data_ps == "shadowsocks":
        out_set["servers"] = [
            {
                "email": "love@v2ray.com",
                "address": config_from["server"],
                "port": config_from["server_port"],
                "method": "aes-128-gcm",
                "password": ss_passwd,
                "ota": False,
                "level": 0
            }
        ]
    elif data_ps == "socks":
        out_set["servers"] = [{
            "address": config_from["server"],
            "port": config_from["server_port"],
        }]
    elif data_ps == "mtproto":
        use_c = False
        use_re = False

    if network == "tcp":
        stream["tcpSettings"] = {}
    elif network == "kcp":
        stream["kcpSettings"] = {}
    elif network == "ws":
        use_re = True
        stream["wsSettings"] = {
            "path": config_from["ws_path"],
        }
    elif network == "http":
        use_re = True
        stream["httpSettings"] = {
            "path": config_from["ws_path"],
            "host": [server_name]
        }
    elif network == "quic":
        stream["quicSettings"] = {
            "security": "aes-128-gcm",
            "key": "",
            "header": {
                "type": "none"
            }
        }
        # todo: quic
    if config_from["tls"] == 1:
        stream["tlsSettings"] = {
            "serverName": server_name,
        }

    outbounds.append(outbound)
    outbounds.append(
        {
            "tag": "direct",
            "protocol": "freedom",
            "settings": {}
        })
    outbounds.append(
        {
            "tag": "blocked",
            "protocol": "blackhole",
            "settings": {}
        })

    routing["domainStrategy"] = "IPOnDemand"
    routing["rules"] = []

    rule = {
        "type": "field",
        "ip": [
            "geoip:private"
        ],
        "outboundTag": "direct"
    }

    routing["rules"].append(rule)

    cn_in_tag = []

    for i, c in enumerate(inbounds):
        if config_from["in"][i]["route"] == 1:
            cn_in_tag.append(c["tag"])

    if len(cn_in_tag) > 0:
        rule = {
            "type": "field",
            "ip": [
                "geoip:cn"
            ],
            "inboundTag": cn_in_tag,
            "outboundTag": "direct"
        }
        routing["rules"].append(rule)

    js_c = json.dumps(v2ray_config_c, sort_keys=False, indent=2, separators=(',', ':'))

    v2ray_config_s["log"] = {
        "access": "/var/log/v2ray/access.log",
        "error": "/var/log/v2ray/error.log",
        "loglevel": "warning"
    }

    inbounds = v2ray_config_s["inbounds"];
    outbounds = v2ray_config_s["outbounds"];
    routing = v2ray_config_s["routing"];

    outbounds.append(
        {
            "tag": "direct",
            "protocol": "freedom",
            "settings": {}
        })
    outbounds.append(
        {
            "tag": "blocked",
            "protocol": "blackhole",
            "settings": {}
        })

    routing["domainStrategy"] = "AsIs"
    routing["rules"] = []

    rule = {
        "type": "field",
        "ip": [
            "geoip:private"
        ],
        "outboundTag": "blocked"
    }

    routing["rules"].append(rule)

    inbound = {
        "port": config_from["server_port"],
        "protocol": data_ps,
        "settings": {},
        "tag": "in-" + str(len(inbounds)),
        "streamSettings": {
            "network": trans_protocol[config_from["trans_protocol"]],
            "security": use_tls[config_from["tls"]],
        }
    }

    tls_should_be_config = False

    stream = inbound["streamSettings"]

    if config_from["tls"] == 1:
        tls_should_be_config = True
        if config_from["reversed_proxy"] != 0 and trans_protocol[config_from["trans_protocol"]] == "ws":
            tls_should_be_config = False
            stream["security"] = use_tls[0]

    if config_from["reversed_proxy"] != 0 and (trans_protocol[config_from["trans_protocol"]] == "ws" or trans_protocol[
        config_from["trans_protocol"]] == "http"):
        inbound["port"] = local_port
        inbound["listen"] = "127.0.0.1"

    if data_ps == "vmess":
        inbound["settings"] = {
            "clients": [
                {
                    "id": vmess_uuid,
                    "alterId": 32,
                }
            ],
        }
    elif data_ps == "shadowsocks":
        inbound["settings"] = {
            "email": "love@v2ray.com",
            "method": "aes-128-gcm",
            "password": ss_passwd,
            "level": 0,
            "ota": False,
            "network": "tcp,udp"
        }
        if trans_protocol[config_from["trans_protocol"]] == "kcp":
            inbound["settings"]["network"] = "tcp"
    elif data_ps == "socks":
        inbound["settings"] = {
            "auth": "noauth",
            "udp": True,
            "ip": "127.0.0.1",
            "userLevel": 0
        }
    elif data_ps == "mtproto":
        add_a_mtproto(inbound, outbounds, inbound["port"], 'in-tag')

    if network == "tcp":
        stream["tcpSettings"] = {}
    elif network == "kcp":
        stream["kcpSettings"] = {}
    elif network == "ws":
        stream["wsSettings"] = {
            "path": config_from["ws_path"],
        }
    elif network == "http":
        stream["httpSettings"] = {
            "path": config_from["ws_path"],
            "host": [server_name]
        }
    if tls_should_be_config:
        stream["tlsSettings"] = {
            "certificates": [
                {
                    "certificateFile": config_from["tls_file"],
                    "keyFile": config_from["tls_key"]
                }
            ]
        }

    inbounds.append(inbound)

    if config_from["extra_mtproto"]:
        extra_in = copy.deepcopy(inbound)
        add_a_mtproto(extra_in, outbounds, inbound["port"] + 1000, 'in-etag')
        inbounds.append(extra_in)

    tg_in_tag = []
    for c in inbounds:
        if c["protocol"] == "mtproto":
            tg_in_tag.append(c["tag"])

    if len(tg_in_tag) > 0:
        rule = {
            "type": "field",
            "inboundTag": tg_in_tag,
            "outboundTag": "out-tg"
        }
        routing["rules"].append(rule)
        outbounds.append(
            {
                "tag": "out-tg",
                "protocol": "mtproto",
                "settings": {}
            })

    js_s = json.dumps(v2ray_config_s, sort_keys=False, indent=2, separators=(',', ': '))
    conf_reversed = None

    if config_from["reversed_proxy"] == 1:
        port = config_from["server_port"]
        tls_file = config_from["tls_file"]
        tls_key = config_from["tls_key"]
        tls_config = ""
        ssl = "ssl"
        if config_from["tls"] == 1:
            tls_config = '''
    ssl on;                                                         
    ssl_certificate       ''' + tls_file + ';' + '''  
    ssl_certificate_key   ''' + tls_key + ';' + '''
    ssl_protocols         TLSv1 TLSv1.1 TLSv1.2;                    
    ssl_ciphers           HIGH:!aNULL:!MD5;
'''
        else:
            ssl = ""
        path = config_from["ws_path"]
        be_proxy = "http://" + "127.0.0.1:" + str(local_port)
        conf_reversed = (1, port, server_name, path, be_proxy, tls_config, ssl)
    elif config_from["reversed_proxy"] == 2:
        domain = ""
        tls = ""

        if config_from["tls"] == 1:
            domain = "https://" + server_name + ":" + str(config_from["server_port"])
            tls = "tls veekxt@gmail.com"
        else:
            domain = "http://" + server_name + ":" + str(config_from["server_port"])
        path = config_from["ws_path"]
        be_proxy = "127.0.0.1:" + str(local_port)
        host_domain = '"' + server_name + '"'
        if tls_should_be_config:
            be_proxy = "https://" + be_proxy
        if trans_protocol[config_from["trans_protocol"]] == "ws":
            conf_reversed = (2, domain, tls, path, be_proxy)
        else:
            conf_reversed = (3, domain, path, be_proxy, host_domain)
    else:
        conf_reversed = (0,)
    return (use_c, use_s, use_re, js_c, js_s, conf_reversed)


def add_a_mtproto(inbound, outbounds, port, tag):
    inbound["settings"] = {
        "users": [{
            "email": "love@v2ray.com",
            "level": 0,
            "secret": rand_string('0123456789abcdef0123456789abcdef', 32)
        }]
    }
    inbound["streamSettings"] = {}
    inbound["tag"] = tag
    inbound["protocol"] = "mtproto"
    if port > 65535: port -= 900
    inbound["port"] = port
    inbound["listen"] = "0.0.0.0"


def rand_string(chars, len_c):
    return ''.join(random.sample(chars, len_c))


if __name__ == "__main__":
    (a, b, c, d, e, f) = get_v2ray_config(config_from_t)
    print(d)
    print("================================================")
    print(e)