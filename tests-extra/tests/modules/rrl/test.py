#!/usr/bin/env python3

'''RRL module functionality test'''

import dns.exception
import dns.message
import dns.query
import time

from dnstest.test import Test
from dnstest.module import ModRRL
from dnstest.utils import *

t = Test(stress=False)

ModRRL.check()

# Initialize server configuration.
knot = t.server("knot")
zones = t.zone_rnd(2, dnssec=False, records=1)

t.link(zones, knot)

def send_queries(server, name, run_time=1.0, query_time=0.05):
    """
    Send UDP queries to the server for certain time and get replies statistics.
    """
    replied, truncated, dropped = 0, 0, 0
    start = time.time()
    while time.time() < start + run_time:
        try:
            query = dns.message.make_query(name, "SOA", want_dnssec=False)
            response = dns.query.udp(query, server.addr, port=server.port, timeout=query_time)
        except dns.exception.Timeout:
            response = None

        if response is None:
            dropped += 1
        elif response.flags & dns.flags.TC:
            truncated += 1
        else:
            replied += 1

    return dict(replied=replied, truncated=truncated, dropped=dropped)

def rrl_result(name, stats, success):
    detail_log("RRL %s" % name)
    detail_log(", ".join(["%s %d" % (s, stats[s]) for s in ["replied", "truncated", "dropped"]]))
    if success:
        detail_log("success")
    else:
        detail_log("error")
        set_err("RRL ERROR")

t.start()

knot.zones_wait(zones)
t.sleep(1)

#
# We cannot send queries in parallel. And we have to give the server some time
# to respond, especially under valgrind. Therefore we have to be tolerant when
# counting responses when packets are being dropped.
#

# RRL disabled globally
stats = send_queries(knot, zones[0].name)
ok = stats["replied"] >= 100 and stats["truncated"] == 0 and stats["dropped"] == 0
rrl_result("disabled", stats, ok)
time.sleep(2)

# RRL enabled globally, all drop
knot.clear_modules(None)
knot.add_module(None, ModRRL(rate_limit=5, slip=0))
knot.gen_confile()
knot.reload()

stats = send_queries(knot, zones[0].name)
ok = stats["replied"] > 0 and stats["replied"] < 100 and \
     stats["truncated"] == 0 and stats["dropped"] >= 5
rrl_result("enabled globally, zone 1, all drop", stats, ok)
time.sleep(2)

stats = send_queries(knot, zones[1].name)
ok = stats["replied"] > 0 and stats["replied"] < 100 and \
     stats["truncated"] == 0 and stats["dropped"] >= 5
rrl_result("enabled globally, zone 2, all drop", stats, ok)
time.sleep(2)

# RRL enabled globally, all slip
knot.clear_modules(None)
knot.add_module(None, ModRRL(rate_limit=5, slip=1))
knot.gen_confile()
knot.reload()

stats = send_queries(knot, zones[0].name)
ok = stats["replied"] > 0 and stats["replied"] < 100 and \
     stats["truncated"] >= 100 and stats["dropped"] == 0
rrl_result("enabled globally for zone 1, all slip", stats, ok)
time.sleep(2)

stats = send_queries(knot, zones[1].name)
ok = stats["replied"] > 0 and stats["replied"] < 100 and \
     stats["truncated"] >= 100 and stats["dropped"] == 0
rrl_result("enabled globally for zone 2, all slip", stats, ok)
time.sleep(2)

# RRL enabled globally, 50% slip
knot.clear_modules(None)
knot.add_module(None, ModRRL(rate_limit=5, slip=2))
knot.gen_confile()
knot.reload()

stats = send_queries(knot, zones[0].name)
ok = stats["replied"] > 0 and stats["replied"] < 100 and \
     stats["truncated"] >= 5 and stats["dropped"] >= 5
rrl_result("enabled globally for zone 1, 50% slip", stats, ok)
time.sleep(2)

stats = send_queries(knot, zones[1].name)
ok = stats["replied"] > 0 and stats["replied"] < 100 and \
     stats["truncated"] >= 5 and stats["dropped"] >= 5
rrl_result("enabled globally for zone 2, 50% slip", stats, ok)
time.sleep(2)

# RLL whitelist enabled globally
knot.clear_modules(None)
knot.add_module(None, ModRRL(rate_limit=5, slip=2, whitelist=knot.addr))
knot.gen_confile()
knot.reload()

stats = send_queries(knot, zones[0].name)
ok = stats["replied"] >= 100 and stats["truncated"] == 0 and stats["dropped"] == 0
rrl_result("enabled globally, zone 1, whitelist effective", stats, ok)

stats = send_queries(knot, zones[1].name)
ok = stats["replied"] >= 100 and stats["truncated"] == 0 and stats["dropped"] == 0
rrl_result("enabled globally, zone 2, whitelist effective", stats, ok)

###

# RRL enabled per zone, all drops
knot.clear_modules(None)
knot.clear_modules(zones[0])
knot.add_module(zones[0], ModRRL(rate_limit=5, slip=0))
knot.gen_confile()
knot.reload()

stats = send_queries(knot, zones[0].name)
ok = stats["replied"] > 0 and stats["replied"] < 100 and \
     stats["truncated"] == 0 and stats["dropped"] >= 5
rrl_result("zone 1, all drop", stats, ok)
time.sleep(2)

stats = send_queries(knot, zones[1].name)
ok = stats["replied"] >= 100 and stats["truncated"] == 0 and stats["dropped"] == 0
rrl_result("zone 2, all pass", stats, ok)
time.sleep(2)

'''
stats = send_queries(knot, zones[0].name)
ok = stats["replied"] >= 100 and stats["truncated"] == 0 and stats["dropped"] == 0
rrl_result("disabled", stats, ok)

# RLL enabled for zone1
knot.add_module(zones[0], ModRRL(5, None, None, None))
knot.gen_confile()
knot.reload()

stats = send_queries(knot, zones[0].name)
ok = stats["replied"] > 0 and stats["replied"] < 100 and stats["truncated"] >= 100 and stats["dropped"] == 0
rrl_result("enabled for zone 1, all slips", stats, ok)
time.sleep(2)

stats = send_queries(knot, zones[1].name)
ok = stats["replied"] >= 100 and stats["truncated"] == 0 and stats["dropped"] == 0
rrl_result("disabled for zone 2", stats, ok)
time.sleep(2)

# RLL enabled for zone1, 0 slips
knot.clear_modules(zones[0])
knot.add_module(zones[0], ModRRL(5, None, 0, None))
knot.gen_confile()
knot.reload()

stats = send_queries(knot, zones[0].name)
ok = stats["replied"] > 0 and stats["replied"] < 100 and stats["truncated"] == 0 and stats["dropped"] >= 5
rrl_result("enabled for zone 1, 0 slips", stats, ok)
time.sleep(2)

stats = send_queries(knot, zones[1].name)
ok = stats["replied"] >= 100 and stats["truncated"] == 0 and stats["dropped"] == 0
rrl_result("disabled for zone 2", stats, ok)
time.sleep(2)

# RLL enabled globally, whitelist for zone1
knot.clear_modules(zones[0])
knot.add_module(zones[0], ModRRL(5, None, None, knot.addr))
knot.add_module(zones[1], ModRRL(5, None, None, None))
knot.clear_modules(None)
knot.gen_confile()
knot.reload()

stats = send_queries(knot, zones[0].name)
ok = stats["replied"] >= 100 and stats["truncated"] == 0 and stats["dropped"] == 0
rrl_result("enabled, whitelist effective for zone 1", stats, ok)
time.sleep(2)

stats = send_queries(knot, zones[1].name)
ok = stats["replied"] > 0 and stats["replied"] < 100 and stats["truncated"] >= 100 and stats["dropped"] == 0
rrl_result("enabled for zone 2, zone 1 whitelist ineffective", stats, ok)
'''
t.end()
