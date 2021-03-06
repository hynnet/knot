#!/usr/bin/env python3

'''Test for record addition over IXFR to slave zone which already contains this record'''

from dnstest.test import Test

t = Test()

master = t.server("bind")
slave = t.server("knot")

zone = t.zone("existing.", storage=".")

t.link(zone, master, slave, ixfr=True)

# Insert the record to slave zone file (no SOA serial change).
slave.update_zonefile(zone, version=2)

t.start()

# Wait for zones.
serial = master.zone_wait(zone)
slave.zone_wait(zone)

# Update master file with the record (new SOA serial).
master.update_zonefile(zone, version=1)
master.reload()

# Wait for zones and compare them.
master.zone_wait(zone, serial)
slave.zone_wait(zone, serial)
t.xfr_diff(master, slave, zone)

t.end()
