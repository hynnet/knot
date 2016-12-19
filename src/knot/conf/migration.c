/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "knot/conf/migration.h"
#include "knot/conf/confdb.h"

int conf_migrate(
	conf_t *conf)
{
	if (conf == NULL) {
		return KNOT_EINVAL;
	}

	int ret;

	knot_db_txn_t txn;
	ret = conf->api->txn_begin(conf->db, &txn, 0);
	if (ret != KNOT_EOK) {
		goto migrate_error;
	}

	conf_val_t val;
	ret = conf_db_get(conf, &txn, C_SRV, C_RATE_LIMIT, NULL, 0, &val);
	if (ret != KNOT_EOK) {
		conf->api->txn_abort(&txn);
		goto migrate_error;
	}

	const char *C_MOD_RRL = "\x07""mod-rrldefault";
	const char *MOD_RATE_LIMIT = "\x0A""rate-limit";

	if (val.code == KNOT_EOK && conf_int(&val) > 0) {
		ret = conf_db_set(conf, &txn, C_MOD_RRL, C_ID, CONF_DEFAULT_ID + 1,
		            CONF_DEFAULT_ID[0], NULL, 0);
		ret = conf_db_set(conf, &txn, C_MOD_RRL, MOD_RATE_LIMIT, CONF_DEFAULT_ID + 1,
		            CONF_DEFAULT_ID[0], val.data, val.len);
		ret = conf_db_set(conf, &txn, C_TPL, C_ID, CONF_DEFAULT_ID + 1,
		            CONF_DEFAULT_ID[0], NULL, 0);
		ret = conf_db_set(conf, &txn, C_TPL, C_GLOBAL_MODULE, CONF_DEFAULT_ID + 1,
		            CONF_DEFAULT_ID[0], (uint8_t *)C_MOD_RRL, 16);

		ret = conf_db_unset(conf, &txn, C_SRV, C_RATE_LIMIT, NULL, 0,
		              NULL, 0, true);
		//conf->api->txn_abort(&txn);
		//return KNOT_EOK;
		ret = conf_db_unset(conf, &txn, C_SRV, C_RATE_LIMIT, NULL, 0,
		              NULL, 0, true);
	}

	// Commit new configuration.
	ret = conf->api->txn_commit(&txn);
	if (ret != KNOT_EOK) {
		goto migrate_error;
	}

	ret = conf_refresh_txn(conf);

	ret = KNOT_EOK;
migrate_error:

	return ret;
}
