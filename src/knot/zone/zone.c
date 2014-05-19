/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/stat.h>

#include "common/descriptor.h"
#include "common/evsched.h"
#include "common/lists.h"
#include "knot/zone/node.h"
#include "knot/zone/zone.h"
#include "knot/zone/zonefile.h"
#include "knot/zone/contents.h"
#include "knot/updates/apply.h"
#include "knot/nameserver/requestor.h"
#include "libknot/common.h"
#include "libknot/dname.h"
#include "libknot/dnssec/random.h"
#include "libknot/util/utils.h"
#include "libknot/rdata/soa.h"

/*!
 * \brief Set ACL list from configuration.
 *
 * \param acl      ACL to be created.
 * \param acl_list List of remotes from configuration.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_ENOMEM on failed memory allocation.
 */
static int set_acl(acl_t **acl, list_t* acl_list)
{
	assert(acl);
	assert(acl_list);

	/* Create new ACL. */
	acl_t *new_acl = acl_new();
	if (new_acl == NULL) {
		return KNOT_ENOMEM;
	}

	/* Load ACL rules. */
	conf_remote_t *r = 0;
	WALK_LIST(r, *acl_list) {
		conf_iface_t *cfg_if = r->remote;
		acl_insert(new_acl, &cfg_if->addr, cfg_if->prefix, cfg_if->key);
	}

	*acl = new_acl;

	return KNOT_EOK;
}

static void free_ddns_queue(zone_t *z)
{
	struct request_data *n = NULL;
	node_t *nxt = NULL;
	WALK_LIST_DELSAFE(n, nxt, z->ddns_queue) {
		close(n->fd);
		knot_pkt_free(&n->query);
		rem_node((node_t *)n);
		free(n);
	}
}

zone_t* zone_new(conf_zone_t *conf)
{
	if (!conf) {
		return NULL;
	}

	zone_t *zone = malloc(sizeof(zone_t));
	if (zone == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	memset(zone, 0, sizeof(zone_t));

	zone->name = knot_dname_from_str(conf->name);
	knot_dname_to_lower(zone->name);
	if (zone->name == NULL) {
		free(zone);
		ERR_ALLOC_FAILED;
		return NULL;
	}

	// Configuration
	zone->conf = conf;

	// DDNS
	pthread_mutex_init(&zone->ddns_lock, 0);
	init_list(&zone->ddns_queue);

	// ACLs
	set_acl(&zone->xfr_out,    &conf->acl.xfr_out);
	set_acl(&zone->notify_in,  &conf->acl.notify_in);
	set_acl(&zone->update_in,  &conf->acl.update_in);

	// Initialize events
	zone_events_init(zone);

	return zone;
}

void zone_free(zone_t **zone_ptr)
{
	if (zone_ptr == NULL || *zone_ptr == NULL) {
		return;
	}

	zone_t *zone = *zone_ptr;

	zone_events_deinit(zone);

	knot_dname_free(&zone->name, NULL);

	acl_delete(&zone->xfr_out);
	acl_delete(&zone->notify_in);
	acl_delete(&zone->update_in);
	free_ddns_queue(zone);
	pthread_mutex_destroy(&zone->ddns_lock);

	/* Free assigned config. */
	conf_free_zone(zone->conf);

	/* Free zone contents. */
	zone_contents_deep_free(&zone->contents);

	free(zone);
	*zone_ptr = NULL;
}

changeset_t *zone_change_prepare(changesets_t *chset)
{
	return changesets_create_changeset(chset);
}

int zone_change_commit(zone_contents_t *contents, changesets_t *chset)
{
	assert(contents);

	if (changesets_empty(chset)) {
		return KNOT_EOK;
	}

	/* Apply DNSSEC changeset to the new zone. */
	return apply_changesets_directly(contents, chset);
}

int zone_change_store(zone_t *zone, changesets_t *chset)
{
	assert(zone);
	assert(chset);

	conf_zone_t *conf = zone->conf;

	int ret = journal_store_changesets(chset, conf->ixfr_db, conf->ixfr_fslimit);
	if (ret == KNOT_EBUSY) {
		log_zone_notice("Journal for '%s' is full, flushing.\n", conf->name);

		/* Transaction rolled back, journal released, we may flush. */
		ret = zone_flush_journal(zone);
		if (ret != KNOT_EOK) {
			return ret;
		}

		return journal_store_changesets(chset, conf->ixfr_db, conf->ixfr_fslimit);
	}

	return ret;
}

/*! \note @mvavrusa Moved from zones.c, this needs a common API. */
int zone_change_apply_and_store(changesets_t **chs,
                                zone_t *zone,
                                const char *msgpref,
                                mm_ctx_t *rr_mm)
{
	int ret = KNOT_EOK;

	/* Now, try to apply the changesets to the zone. */
	zone_contents_t *new_contents;
	ret = apply_changesets(zone, *chs, &new_contents);
	if (ret != KNOT_EOK) {
		log_zone_error("%s Failed to apply changesets.\n", msgpref);
		/* Free changesets, but not the data. */
		changesets_free(chs, rr_mm);
		return ret;  // propagate the error above
	}

	/* Write changes to journal if all went well. */
	ret = zone_change_store(zone, *chs);
	if (ret != KNOT_EOK) {
		log_zone_error("%s Failed to store changesets.\n", msgpref);
		update_rollback(*chs, &new_contents);
		/* Free changesets, but not the data. */
		changesets_free(chs, rr_mm);
		return ret;  // propagate the error above
	}

	/* Switch zone contents. */
	zone_contents_t *old_contents = zone_switch_contents(zone, new_contents);
	synchronize_rcu();
	update_free_old_zone(&old_contents);

	/* Free changesets, but not the data. */
	update_cleanup(*chs);
	changesets_free(chs, rr_mm);
	assert(ret == KNOT_EOK);
	return KNOT_EOK;
}

zone_contents_t *zone_switch_contents(zone_t *zone, zone_contents_t *new_contents)
{
	if (zone == NULL) {
		return NULL;
	}

	zone_contents_t *old_contents;
	old_contents = rcu_xchg_pointer(&zone->contents, new_contents);

	return old_contents;
}

const conf_iface_t *zone_master(const zone_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	if (EMPTY_LIST(zone->conf->acl.xfr_in)) {
		return NULL;
	}

	conf_remote_t *master = HEAD(zone->conf->acl.xfr_in);
	return master->remote;
}

void zone_master_rotate(const zone_t *zone)
{

	list_t *master_list = &zone->conf->acl.xfr_in;
	if (list_size(master_list) < 2) {
		return;
	}

	add_tail(master_list, HEAD(*master_list));
}

int zone_flush_journal(zone_t *zone)
{
	/*! @note Function expects nobody will change zone contents meanwile. */

	if (zone == NULL || zone_contents_is_empty(zone->contents)) {
		return KNOT_EINVAL;
	}

	/* Check for difference against zonefile serial. */
	zone_contents_t *contents = zone->contents;
	uint32_t serial_to = zone_contents_serial(contents);
	if (zone->zonefile_serial == serial_to) {
		return KNOT_EOK; /* No differences. */
	}

	/* Fetch zone source (where it came from). */
	const struct sockaddr_storage *from = NULL;
	const conf_iface_t *master = zone_master(zone);
	if (master != NULL) {
		from = &master->addr;
	}

	/* Synchronize journal. */
	conf_zone_t *conf = zone->conf;
	int ret = zonefile_write(conf->file, contents, from);
	if (ret == KNOT_EOK) {
		log_zone_info("Applied differences of '%s' to zonefile.\n", conf->name);
	} else {
		log_zone_warning("Failed to apply differences of '%s' "
		                 "to zonefile (%s).\n", conf->name, knot_strerror(ret));
		return ret;
	}

	/* Update zone version. */
	struct stat st;
	if (stat(zone->conf->file, &st) < 0) {
		log_zone_warning("Failed to apply differences '%s' to '%s (%s)'\n",
		                 conf->name, conf->file, knot_strerror(KNOT_EACCES));
		return KNOT_EACCES;
	}

	/* Update zone file serial and journal. */
	zone->zonefile_mtime = st.st_mtime;
	zone->zonefile_serial = serial_to;
	journal_mark_synced(zone->conf->ixfr_db);

	return ret;
}

int zone_update_enqueue(zone_t *zone, knot_pkt_t *pkt, struct process_query_param *param)
{

	/* Create serialized request. */
	struct request_data *req = malloc(sizeof(struct request_data));
	if (req == NULL) {
		return KNOT_ENOMEM;
	}
	memset(req, 0, sizeof(struct request_data));

	/* Copy socket and request. */
	req->fd = dup(param->socket);
	memcpy(&req->remote, param->remote, sizeof(struct sockaddr_storage));
	req->query = knot_pkt_copy(pkt, NULL);
	if (req->query == NULL) {
		free(req);
		return KNOT_ENOMEM;
	}

	pthread_mutex_lock(&zone->ddns_lock);

	/* Enqueue created request. */
	add_tail(&zone->ddns_queue, (node_t *)req);

	pthread_mutex_unlock(&zone->ddns_lock);

	/* Schedule UPDATE event. If already scheduled, older event will stay. */
	zone_events_schedule(zone, ZONE_EVENT_UPDATE, ZONE_EVENT_NOW);

	return KNOT_EOK;
}

struct request_data *zone_update_dequeue(zone_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	pthread_mutex_lock(&zone->ddns_lock);
	assert(!EMPTY_LIST(zone->ddns_queue));
	struct request_data *ret = HEAD(zone->ddns_queue);
	rem_node((node_t *)ret);
	pthread_mutex_unlock(&zone->ddns_lock);

	return ret;
}

bool zone_transfer_needed(const zone_t *zone, const knot_pkt_t *pkt)
{
	if (zone_contents_is_empty(zone->contents)) {
		return true;
	}

	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);
	const knot_rrset_t soa = answer->rr[0];
	if (soa.type != KNOT_RRTYPE_SOA) {
		return false;
	}

	return knot_serial_compare(zone_contents_serial(zone->contents),
	                           knot_soa_serial(&soa.rrs)) < 0;
}

