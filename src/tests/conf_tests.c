#include <stdio.h>

#include "tap_unit.h"
#include "conf/conf.h"

/* Resources. */
#include "sample_conf.rc"

static int conf_tests_count(int argc, char *argv[]);
static int conf_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api conf_tests_api = {
	"Configuration parser", //! Unit name
	&conf_tests_count,      //! Count scheduled tests
	&conf_tests_run         //! Run scheduled tests
};

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int conf_tests_count(int argc, char *argv[])
{
	return 20;
}

/*! Run all scheduled tests for given parameters.
 */
static int conf_tests_run(int argc, char *argv[])
{

	// Test 1: Allocate new config
	const char *config_fn = "rc:/sample_conf";
	conf_t *conf = conf_new(config_fn);
	ok(conf != 0, "config_new()");

	// Test 2: Parse config
	int ret = conf_parse_str(conf, sample_conf_rc);
	ok(ret == 0, "parsing configuration file %s", config_fn);
	skip(ret != 0, conf_tests_count(argc, argv) - 2);
	{

	// Test 3: Test server version (0-level depth)
	is(conf->version, "Infinitesimal", "server version loaded ok");

	// Test 4: Test interfaces (1-level depth)
	ok(!EMPTY_LIST(conf->ifaces), "configured interfaces exist");

	// Test 5,6,7,8: Interfaces content (2-level depth)
	struct node *n = HEAD(conf->ifaces);
	conf_iface_t *iface = (conf_iface_t*)n;
	is(iface->address, "10.10.1.1", "interface0 address check");
	cmp_ok(iface->port, "==", 53531, "interface0 port check");
	n = n->next;
	iface = (conf_iface_t*)n;
	is(iface->address, "::0", "interface1 address check");
	cmp_ok(iface->port, "==", 53, "interface1 default port check");

	// Test 9,10: Check server key
	cmp_ok(conf->key.algorithm, "==", HMAC_MD5, "TSIG key algorithm check");
	is(conf->key.secret, "Wg==", "TSIG key secret check");

	// Test 11,12,13,14,15,16,17,18: Check logging facilities
	cmp_ok(conf->logs_count, "==", 4, "log facilites count check");
	n = HEAD(conf->logs);
	ok(!EMPTY_LIST(conf->logs), "log facilities not empty");

	conf_log_t *log = (conf_log_t*)n;
	node *nm = HEAD(log->map);
	conf_log_map_t *m = (conf_log_map_t*)nm;
	cmp_ok(log->type, "==", LOGT_SYSLOG, "log0 is syslog");

	skip(EMPTY_LIST(log->map), 5);
	{
	  cmp_ok(m->source, "==", LOG_ANY, "syslog first rule is ANY");
	  int mask = LOG_MASK(LOG_NOTICE)|LOG_MASK(LOG_WARNING)|LOG_MASK(LOG_ERR);
	  cmp_ok(m->prios, "==", mask, "syslog mask is equal");
	  nm = nm->next;
	  m = (conf_log_map_t*)nm;
	  ok(m != 0, "syslog has more than 1 rule");
	  skip(!m, 2);
	  {
	    cmp_ok(m->source, "==", LOG_ZONE, "syslog next rule is for zone");
	    cmp_ok(m->prios, "==", 0xff, "rule for zone is: any level");
	  }
	  endskip;
	}
	endskip;

	// Test 19,20: File facility checks
	n = n->next;
	log = (conf_log_t*)n;
	ok(n != 0, "log has next facility");
	skip(!n, 1);
	{
	  is(log->file, "/var/log/cutedns/server.err", "log file matches");
	}
	endskip;

	}
	endskip;

	// Deallocating config
	conf_free(conf);

	return 0;
}
