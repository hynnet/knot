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

#include <string.h>
#include <unistd.h>

#include "knot/common/log.h"
#include "knot/conf/confio.h"
#include "knot/ctl/commands.h"
#include "knot/events/handlers.h"
#include "knot/updates/zone-update.h"
#include "knot/zone/timers.h"
#include "libknot/libknot.h"
#include "libknot/yparser/yptrafo.h"
#include "contrib/macros.h"
#include "contrib/mempattern.h"
#include "contrib/string.h"
#include "zscanner/scanner.h"

void ctl_log_data(knot_ctl_data_t *data)
{
	if (data == NULL) {
		return;
	}

	const char *zone = (*data)[KNOT_CTL_IDX_ZONE];
	const char *section = (*data)[KNOT_CTL_IDX_SECTION];
	const char *item = (*data)[KNOT_CTL_IDX_ITEM];
	const char *id = (*data)[KNOT_CTL_IDX_ID];

	if (section == NULL) {
		return;
	}

	if (zone != NULL) {
		log_ctl_zone_str_debug(zone,
		              "control, item '%s%s%s%s%s%s'", section,
		              (id   != NULL ? "["  : ""),
		              (id   != NULL ? id   : ""),
		              (id   != NULL ? "]"  : ""),
		              (item != NULL ? "."  : ""),
		              (item != NULL ? item : ""));
	} else {
		log_ctl_debug("control, item '%s%s%s%s%s%s'", section,
		              (id   != NULL ? "["  : ""),
		              (id   != NULL ? id   : ""),
		              (id   != NULL ? "]"  : ""),
		              (item != NULL ? "."  : ""),
		              (item != NULL ? item : ""));
	}
}

static void send_error(ctl_args_t *args, const char *msg)
{
	knot_ctl_data_t data;
	memcpy(&data, args->data, sizeof(data));

	data[KNOT_CTL_IDX_ERROR] = msg;

	int ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_DATA, &data);
	if (ret != KNOT_EOK) {
		log_ctl_debug("control, failed to send error (%s)", knot_strerror(ret));
	}
}

static int get_zone(ctl_args_t *args, zone_t **zone)
{
	const char *name = args->data[KNOT_CTL_IDX_ZONE];
	assert(name != NULL);

	uint8_t buff[KNOT_DNAME_MAXLEN];

	knot_dname_t *dname = knot_dname_from_str(buff, name, sizeof(buff));
	if (dname == NULL) {
		return KNOT_EINVAL;
	}

	int ret = knot_dname_to_lower(dname);
	if (ret != KNOT_EOK) {
		return ret;
	}

	*zone = knot_zonedb_find(args->server->zone_db, dname);
	if (*zone == NULL) {
		return KNOT_ENOZONE;
	}

	return KNOT_EOK;
}

static int zones_apply(ctl_args_t *args, int (*fcn)(zone_t *, ctl_args_t *))
{
	// Process all configured zones if none is specified.
	if (args->data[KNOT_CTL_IDX_ZONE] == NULL) {
		knot_zonedb_foreach(args->server->zone_db, fcn, args);
		return KNOT_EOK;
	}

	int ret = KNOT_EOK;

	while (true) {
		zone_t *zone;
		ret = get_zone(args, &zone);
		if (ret == KNOT_EOK) {
			ret = fcn(zone, args);
		}
		if (ret != KNOT_EOK) {
			log_ctl_zone_str_error(args->data[KNOT_CTL_IDX_ZONE],
			                       "control, error (%s)", knot_strerror(ret));
			send_error(args, knot_strerror(ret));
		}

		// Get next zone name.
		ret = knot_ctl_receive(args->ctl, &args->type, &args->data);
		if (ret != KNOT_EOK || args->type != KNOT_CTL_TYPE_DATA) {
			break;
		}
		ctl_log_data(&args->data);
	}

	return ret;
}

static int zone_status(zone_t *zone, ctl_args_t *args)
{
	// Zone name.
	char name[KNOT_DNAME_TXT_MAXLEN + 1];
	if (knot_dname_to_str(name, zone->name, sizeof(name)) == NULL) {
		return KNOT_EINVAL;
	}

	knot_ctl_data_t data = {
		[KNOT_CTL_IDX_ZONE] = name
	};

	// Zone type.
	data[KNOT_CTL_IDX_TYPE] = "type";

	if (zone_is_slave(conf(), zone)) {
		data[KNOT_CTL_IDX_DATA] = "slave";
	} else {
		data[KNOT_CTL_IDX_DATA] = "master";
	}

	int ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_DATA, &data);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Zone serial.
	data[KNOT_CTL_IDX_TYPE] = "serial";

	char buff[128];
	if (zone->contents != NULL) {
		knot_rdataset_t *soa = node_rdataset(zone->contents->apex,
		                                     KNOT_RRTYPE_SOA);
		ret = snprintf(buff, sizeof(buff), "%u", knot_soa_serial(soa));
	} else {
		ret = snprintf(buff, sizeof(buff), "none");
	}
	if (ret < 0 || ret >= sizeof(buff)) {
		return KNOT_ESPACE;
	}

	data[KNOT_CTL_IDX_DATA] = buff;

	ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_EXTRA, &data);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Next event.
	data[KNOT_CTL_IDX_TYPE] = "next-event";

	zone_event_type_t next_type = ZONE_EVENT_INVALID;
	time_t next_time = zone_events_get_next(zone, &next_type);
	if (next_type != ZONE_EVENT_INVALID) {
		const char *next_name = zone_events_get_name(next_type);

		next_time = next_time - time(NULL);
		if (next_time < 0) {
			ret = snprintf(buff, sizeof(buff), "%s pending",
			               next_name);
		} else {
			ret = snprintf(buff, sizeof(buff), "%s in %lldh%lldm%llds",
			               next_name,
			               (long long)(next_time / 3600),
			               (long long)(next_time % 3600) / 60,
			               (long long)(next_time % 60));
		}
		if (ret < 0 || ret >= sizeof(buff)) {
			return KNOT_ESPACE;
		}

		data[KNOT_CTL_IDX_DATA] = buff;
	} else {
		data[KNOT_CTL_IDX_DATA] = "idle";
	}

	ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_EXTRA, &data);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// DNSSEC re-signing time.
	data[KNOT_CTL_IDX_TYPE] = "auto-dnssec";

	conf_val_t val = conf_zone_get(conf(), C_DNSSEC_SIGNING, zone->name);
	if (conf_bool(&val)) {
		struct tm time_gm = { 0 };
		time_t refresh_at = zone_events_get_time(zone, ZONE_EVENT_DNSSEC);
		gmtime_r(&refresh_at, &time_gm);

		size_t written = strftime(buff, sizeof(buff), KNOT_LOG_TIME_FORMAT,
		                          &time_gm);
		if (written == 0) {
			return KNOT_ESPACE;
		}

		data[KNOT_CTL_IDX_DATA] = buff;
	} else {
		data[KNOT_CTL_IDX_DATA] = "disabled";
	}

	ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_EXTRA, &data);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Zone transaction.
	data[KNOT_CTL_IDX_TYPE] = "transaction";
	data[KNOT_CTL_IDX_DATA] = (zone->control_update != NULL) ? "open" : "none";

	return knot_ctl_send(args->ctl, KNOT_CTL_TYPE_EXTRA, &data);
}

static int zone_reload(zone_t *zone, ctl_args_t *args)
{
	UNUSED(args);

	if (zone->flags & ZONE_EXPIRED) {
		return KNOT_ENOTSUP;
	}

	zone_events_schedule(zone, ZONE_EVENT_LOAD, ZONE_EVENT_NOW);

	return KNOT_EOK;
}

static int zone_refresh(zone_t *zone, ctl_args_t *args)
{
	UNUSED(args);

	if (!zone_is_slave(conf(), zone)) {
		return KNOT_ENOTSUP;
	}

	zone_events_schedule(zone, ZONE_EVENT_REFRESH, ZONE_EVENT_NOW);

	return KNOT_EOK;
}

static int zone_retransfer(zone_t *zone, ctl_args_t *args)
{
	UNUSED(args);

	if (!zone_is_slave(conf(), zone)) {
		return KNOT_ENOTSUP;
	}

	zone->flags |= ZONE_FORCE_AXFR;
	zone_events_schedule(zone, ZONE_EVENT_XFER, ZONE_EVENT_NOW);

	return KNOT_EOK;
}

static int zone_flush(zone_t *zone, ctl_args_t *args)
{
	UNUSED(args);

	if (ctl_has_flag(args->data[KNOT_CTL_IDX_FLAGS], CTL_FLAG_FORCE)) {
		zone->flags |= ZONE_FORCE_FLUSH;
	}

	zone_events_schedule(zone, ZONE_EVENT_FLUSH, ZONE_EVENT_NOW);

	return KNOT_EOK;
}

static int zone_sign(zone_t *zone, ctl_args_t *args)
{
	UNUSED(args);

	conf_val_t val = conf_zone_get(conf(), C_DNSSEC_SIGNING, zone->name);
	if (!conf_bool(&val)) {
		return KNOT_ENOTSUP;
	}

	zone->flags |= ZONE_FORCE_RESIGN;
	zone_events_schedule(zone, ZONE_EVENT_DNSSEC, ZONE_EVENT_NOW);

	return KNOT_EOK;
}

static int zone_txn_begin(zone_t *zone, ctl_args_t *args)
{
	UNUSED(args);

	if (zone->control_update != NULL) {
		return KNOT_TXN_EEXISTS;
	}

	zone->control_update = malloc(sizeof(zone_update_t));
	if (zone->control_update == NULL) {
		return KNOT_ENOMEM;
	}

	zone_update_flags_t type = (zone->contents == NULL) ? UPDATE_FULL : UPDATE_INCREMENTAL;
	int ret = zone_update_init(zone->control_update, zone, type | UPDATE_SIGN | UPDATE_STRICT);
	if (ret != KNOT_EOK) {
		free(zone->control_update);
		zone->control_update = NULL;
		return ret;
	}

	return KNOT_EOK;
}

static int zone_txn_commit(zone_t *zone, ctl_args_t *args)
{
	UNUSED(args);

	if (zone->control_update == NULL) {
		return KNOT_TXN_ENOTEXISTS;
	}

	int ret = zone_update_commit(conf(), zone->control_update);
	if (ret != KNOT_EOK) {
		/* Invalidate the transaction if aborted. */
		if (zone->control_update->zone == NULL) {
			free(zone->control_update);
			zone->control_update = NULL;
		}
		return ret;
	}

	zone_update_clear(zone->control_update);
	free(zone->control_update);
	zone->control_update = NULL;

	/* Sync zonefile immediately if configured. */
	conf_val_t val = conf_zone_get(conf(), C_ZONEFILE_SYNC, zone->name);
	if (conf_int(&val) == 0) {
		zone_events_schedule(zone, ZONE_EVENT_FLUSH, ZONE_EVENT_NOW);
	}

	zone_events_schedule(zone, ZONE_EVENT_NOTIFY, ZONE_EVENT_NOW);

	return KNOT_EOK;
}

static int zone_txn_abort(zone_t *zone, ctl_args_t *args)
{
	UNUSED(args);

	if (zone->control_update == NULL) {
		return KNOT_TXN_ENOTEXISTS;
	}

	zone_update_clear(zone->control_update);
	free(zone->control_update);
	zone->control_update = NULL;

	return KNOT_EOK;
}

typedef struct {
	ctl_args_t *args;
	int type_filter; // -1: no specific type, [0, 2^16]: specific type.
	knot_dump_style_t style;
	knot_ctl_data_t data;
	char zone[KNOT_DNAME_TXT_MAXLEN + 1];
	char owner[KNOT_DNAME_TXT_MAXLEN + 1];
	char ttl[16];
	char type[32];
	char rdata[2 * 65536];
} send_ctx_t;

static send_ctx_t *create_send_ctx(const knot_dname_t *zone_name, ctl_args_t *args)
{
	send_ctx_t *ctx = mm_alloc(&args->mm, sizeof(*ctx));
	if (ctx == NULL) {
		return NULL;
	}
	memset(ctx, 0, sizeof(*ctx));

	ctx->args = args;

	// Set the dump style.
	ctx->style.show_ttl = true;
	ctx->style.human_tmstamp = true;

	// Set the output data buffers.
	ctx->data[KNOT_CTL_IDX_ZONE]  = ctx->zone;
	ctx->data[KNOT_CTL_IDX_OWNER] = ctx->owner;
	ctx->data[KNOT_CTL_IDX_TTL]   = ctx->ttl;
	ctx->data[KNOT_CTL_IDX_TYPE]  = ctx->type;
	ctx->data[KNOT_CTL_IDX_DATA]  = ctx->rdata;

	// Set the ZONE.
	if (knot_dname_to_str(ctx->zone, zone_name, sizeof(ctx->zone)) == NULL) {
		mm_free(&args->mm, ctx);
		return NULL;
	}

	// Set the TYPE filter.
	if (args->data[KNOT_CTL_IDX_TYPE] != NULL) {
		uint16_t type;
		if (knot_rrtype_from_string(args->data[KNOT_CTL_IDX_TYPE], &type) != 0) {
			mm_free(&args->mm, ctx);
			return NULL;
		}
		ctx->type_filter = type;
	} else {
		ctx->type_filter = -1;
	}

	return ctx;
}

static int send_rrset(knot_rrset_t *rrset, send_ctx_t *ctx)
{
	int ret = snprintf(ctx->ttl, sizeof(ctx->ttl), "%u", knot_rrset_ttl(rrset));
	if (ret <= 0 || ret >= sizeof(ctx->ttl)) {
		return KNOT_ESPACE;
	}

	if (knot_rrtype_to_string(rrset->type, ctx->type, sizeof(ctx->type)) < 0) {
		return KNOT_ESPACE;
	}

	for (size_t i = 0; i < rrset->rrs.rr_count; ++i) {
		ret = knot_rrset_txt_dump_data(rrset, i, ctx->rdata,
		                               sizeof(ctx->rdata), &ctx->style);
		if (ret < 0) {
			return ret;
		}

		ret = knot_ctl_send(ctx->args->ctl, KNOT_CTL_TYPE_DATA, &ctx->data);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static int send_node(zone_node_t *node, void *ctx_void)
{
	send_ctx_t *ctx = ctx_void;
	if (knot_dname_to_str(ctx->owner, node->owner, sizeof(ctx->owner)) == NULL) {
		return KNOT_EINVAL;
	}

	for (size_t i = 0; i < node->rrset_count; ++i) {
		knot_rrset_t rrset = node_rrset_at(node, i);

		// Check for requested TYPE.
		if (ctx->type_filter != -1 && rrset.type != ctx->type_filter) {
			continue;
		}

		int ret = send_rrset(&rrset, ctx);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static int get_owner(uint8_t *out, size_t out_len, knot_dname_t *origin,
                     ctl_args_t *args)
{
	const char *owner = args->data[KNOT_CTL_IDX_OWNER];
	assert(owner != NULL);

	bool fqdn = false;
	int prefix_len = 0;

	size_t owner_len = strlen(owner);
	if (owner_len > 0 && (owner_len != 1 || owner[0] != '@')) {
		// Check if the owner is FQDN.
		if (owner[owner_len - 1] == '.') {
			fqdn = true;
		}

		knot_dname_t *dname = knot_dname_from_str(out, owner, out_len);
		if (dname == NULL) {
			return KNOT_EINVAL;
		}

		int ret = knot_dname_to_lower(dname);
		if (ret != KNOT_EOK) {
			return ret;
		}

		prefix_len = knot_dname_size(out);
		if (prefix_len <= 0) {
			return KNOT_EINVAL;
		}

		// Ignore trailing dot.
		prefix_len--;
	}

	// Append the origin.
	if (!fqdn) {
		int origin_len = knot_dname_size(origin);
		if (origin_len <= 0 || origin_len > out_len - prefix_len) {
			return KNOT_EINVAL;
		}
		memcpy(out + prefix_len, origin, origin_len);
	}

	return KNOT_EOK;
}

static int zone_read(zone_t *zone, ctl_args_t *args)
{
	send_ctx_t *ctx = create_send_ctx(zone->name, args);
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = KNOT_EOK;

	if (args->data[KNOT_CTL_IDX_OWNER] != NULL) {
		uint8_t owner[KNOT_DNAME_MAXLEN];

		ret = get_owner(owner, sizeof(owner), zone->name, args);
		if (ret != KNOT_EOK) {
			goto zone_read_failed;
		}

		const zone_node_t *node = zone_contents_find_node(zone->contents, owner);
		if (node == NULL) {
			ret = KNOT_ENONODE;
			goto zone_read_failed;
		}

		ret = send_node((zone_node_t *)node, ctx);
	} else if (zone->contents != NULL) {
		ret = zone_contents_apply(zone->contents, send_node, ctx);
	}

zone_read_failed:
	mm_free(&args->mm, ctx);

	return ret;
}

static int zone_flag_txn_get(zone_t *zone, ctl_args_t *args, const char *flag)
{
	if (zone->control_update == NULL) {
		return KNOT_TXN_ENOTEXISTS;
	}

	send_ctx_t *ctx = create_send_ctx(zone->name, args);
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}
	ctx->data[KNOT_CTL_IDX_FLAGS] = flag;

	int ret = KNOT_EOK;

	if (args->data[KNOT_CTL_IDX_OWNER] != NULL) {
		uint8_t owner[KNOT_DNAME_MAXLEN];

		ret = get_owner(owner, sizeof(owner), zone->name, args);
		if (ret != KNOT_EOK) {
			goto zone_txn_get_failed;
		}

		const zone_node_t *node = zone_update_get_node(zone->control_update, owner);
		if (node == NULL) {
			ret = KNOT_ENONODE;
			goto zone_txn_get_failed;
		}

		ret = send_node((zone_node_t *)node, ctx);
	} else {
		zone_update_iter_t it;
		ret = zone_update_iter(&it, zone->control_update);
		if (ret != KNOT_EOK) {
			goto zone_txn_get_failed;
		}

		const zone_node_t *iter_node = zone_update_iter_val(&it);
		while (iter_node != NULL) {
			ret = send_node((zone_node_t *)iter_node, ctx);
			if (ret != KNOT_EOK) {
				zone_update_iter_finish(&it);
				goto zone_txn_get_failed;
			}

			ret = zone_update_iter_next(&it);
			if (ret != KNOT_EOK) {
				zone_update_iter_finish(&it);
				goto zone_txn_get_failed;
			}

			iter_node = zone_update_iter_val(&it);
		}
		zone_update_iter_finish(&it);
	}

zone_txn_get_failed:
	mm_free(&args->mm, ctx);

	return ret;
}

static int zone_txn_get(zone_t *zone, ctl_args_t *args)
{
	return zone_flag_txn_get(zone, args, NULL);
}

static int send_changeset_part(changeset_t *ch, send_ctx_t *ctx, bool from)
{
	ctx->data[KNOT_CTL_IDX_FLAGS] = from ? CTL_FLAG_REM : CTL_FLAG_ADD;

	// Send SOA only if explicitly changed.
	if (ch->soa_to != NULL) {
		knot_rrset_t *soa = from ? ch->soa_from : ch->soa_to;
		assert(soa);

		char *owner = knot_dname_to_str(ctx->owner, soa->owner, sizeof(ctx->owner));
		if (owner == NULL) {
			return KNOT_EINVAL;
		}

		int ret = send_rrset(soa, ctx);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	// Send other records.
	changeset_iter_t it;
	int ret = from ? changeset_iter_rem(&it, ch) : changeset_iter_add(&it, ch);
	if (ret != KNOT_EOK) {
		return ret;
	}

	knot_rrset_t rrset = changeset_iter_next(&it);
	while (!knot_rrset_empty(&rrset)) {
		char *owner = knot_dname_to_str(ctx->owner, rrset.owner, sizeof(ctx->owner));
		if (owner == NULL) {
			changeset_iter_clear(&it);
			return KNOT_EINVAL;
		}

		ret = send_rrset(&rrset, ctx);
		if (ret != KNOT_EOK) {
			changeset_iter_clear(&it);
			return ret;
		}

		rrset = changeset_iter_next(&it);
	}
	changeset_iter_clear(&it);

	return KNOT_EOK;
}

static int send_changeset(changeset_t *ch, send_ctx_t *ctx)
{
	// First send 'from' changeset part.
	int ret = send_changeset_part(ch, ctx, true);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Second send 'to' changeset part.
	ret = send_changeset_part(ch, ctx, false);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return KNOT_EOK;
}

static int zone_txn_diff(zone_t *zone, ctl_args_t *args)
{
	if (zone->control_update == NULL) {
		return KNOT_TXN_ENOTEXISTS;
	}

	// FULL update has no changeset to print, do a 'get' instead.
	if (zone->control_update->flags & UPDATE_FULL) {
		return zone_flag_txn_get(zone, args, CTL_FLAG_ADD);
	}

	send_ctx_t *ctx = create_send_ctx(zone->name, args);
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = send_changeset(&zone->control_update->change, ctx);
	mm_free(&args->mm, ctx);
	return ret;
}

static int get_ttl(zone_t *zone, ctl_args_t *args, uint32_t *ttl)
{
	uint8_t owner[KNOT_DNAME_MAXLEN];

	int ret = get_owner(owner, sizeof(owner), zone->name, args);
	if (ret != KNOT_EOK) {
		return ret;
	}

	const zone_node_t *node = zone_update_get_node(zone->control_update, owner);
	if (node == NULL) {
		return KNOT_ETTL;
	}

	uint16_t type;
	if (knot_rrtype_from_string(args->data[KNOT_CTL_IDX_TYPE], &type) != 0) {
		return KNOT_EINVAL;
	}

	knot_rdataset_t *rdataset = node_rdataset(node, type);
	if (rdataset == NULL) {
		return KNOT_ETTL;
	}

	*ttl = knot_rdataset_ttl(rdataset);

	return KNOT_EOK;
}

static int create_rrset(knot_rrset_t **rrset, zone_t *zone, ctl_args_t *args,
                        bool need_ttl)
{
	char origin_buff[KNOT_DNAME_TXT_MAXLEN + 1];
	char *origin = knot_dname_to_str(origin_buff, zone->name, sizeof(origin_buff));
	if (origin == NULL) {
		return KNOT_EINVAL;
	}

	const char *owner = args->data[KNOT_CTL_IDX_OWNER];
	const char *type  = args->data[KNOT_CTL_IDX_TYPE];
	const char *data  = args->data[KNOT_CTL_IDX_DATA];
	const char *ttl   = need_ttl ? args->data[KNOT_CTL_IDX_TTL] : NULL;

	// Prepare a buffer for a reconstructed record.
	const size_t buff_len = sizeof(((send_ctx_t *)0)->owner) +
	                        sizeof(((send_ctx_t *)0)->ttl) +
	                        sizeof(((send_ctx_t *)0)->type) +
	                        sizeof(((send_ctx_t *)0)->rdata);
	char *buff = mm_alloc(&args->mm, buff_len);
	if (buff == NULL) {
		return KNOT_ENOMEM;
	}

	uint32_t default_ttl = 0;
	if (ttl == NULL) {
		int ret = get_ttl(zone, args, &default_ttl);
		if (need_ttl && ret != KNOT_EOK) {
			mm_free(&args->mm, buff);
			return ret;
		}
	}

	// Reconstruct the record.
	int ret = snprintf(buff, buff_len, "%s %s %s %s\n",
	                   (owner != NULL ? owner : ""),
	                   (ttl   != NULL ? ttl   : ""),
	                   (type  != NULL ? type  : ""),
	                   (data  != NULL ? data  : ""));
	if (ret <= 0 || ret >= buff_len) {
		mm_free(&args->mm, buff);
		return KNOT_ESPACE;
	}
	size_t rdata_len = ret;

	// Initialize RR parser.
	zs_scanner_t *scanner = mm_alloc(&args->mm, sizeof(*scanner));
	if (scanner == NULL) {
		ret = KNOT_ENOMEM;
		goto parser_failed;
	}

	// Parse the record.
	if (zs_init(scanner, origin, KNOT_CLASS_IN, default_ttl) != 0 ||
	    zs_set_input_string(scanner, buff, rdata_len) != 0 ||
	    zs_parse_record(scanner) != 0 ||
	    scanner->state != ZS_STATE_DATA) {
		ret = KNOT_EPARSEFAIL;
		goto parser_failed;
	}

	// Create output rrset.
	*rrset = knot_rrset_new(scanner->r_owner, scanner->r_type,
	                        scanner->r_class, NULL);
	if (*rrset == NULL) {
		ret = KNOT_ENOMEM;
		goto parser_failed;
	}

	ret = knot_rrset_add_rdata(*rrset, scanner->r_data, scanner->r_data_length,
	                           scanner->r_ttl, NULL);
parser_failed:
	zs_deinit(scanner);
	mm_free(&args->mm, scanner);
	mm_free(&args->mm, buff);

	return ret;
}

static int zone_txn_set(zone_t *zone, ctl_args_t *args)
{
	if (zone->control_update == NULL) {
		return KNOT_TXN_ENOTEXISTS;
	}

	if (args->data[KNOT_CTL_IDX_OWNER] == NULL ||
	    args->data[KNOT_CTL_IDX_TYPE]  == NULL) {
		return KNOT_EINVAL;
	}

	knot_rrset_t *rrset;
	int ret = create_rrset(&rrset, zone, args, true);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = zone_update_add(zone->control_update, rrset);
	knot_rrset_free(&rrset, NULL);

	// Silently update TTL.
	if (ret == KNOT_ETTL) {
		ret = KNOT_EOK;
	}

	return ret;
}

static int zone_txn_unset(zone_t *zone, ctl_args_t *args)
{
	if (zone->control_update == NULL) {
		return KNOT_TXN_ENOTEXISTS;
	}

	if (args->data[KNOT_CTL_IDX_OWNER] == NULL) {
		return KNOT_EINVAL;
	}

	// Remove specific record.
	if (args->data[KNOT_CTL_IDX_DATA] != NULL) {
		if (args->data[KNOT_CTL_IDX_TYPE] == NULL) {
			return KNOT_EINVAL;
		}

		knot_rrset_t *rrset;
		int ret = create_rrset(&rrset, zone, args, false);
		if (ret != KNOT_EOK) {
			return ret;
		}

		ret = zone_update_remove(zone->control_update, rrset);
		knot_rrset_free(&rrset, NULL);
		return ret;
	} else {
		uint8_t owner[KNOT_DNAME_MAXLEN];

		int ret = get_owner(owner, sizeof(owner), zone->name, args);
		if (ret != KNOT_EOK) {
			return ret;
		}

		// Remove whole rrset.
		if (args->data[KNOT_CTL_IDX_TYPE] != NULL) {
			uint16_t type;
			if (knot_rrtype_from_string(args->data[KNOT_CTL_IDX_TYPE],
			                            &type) != 0) {
				return KNOT_EINVAL;
			}

			return zone_update_remove_rrset(zone->control_update, owner, type);
		// Remove whole node.
		} else {
			return zone_update_remove_node(zone->control_update, owner);
		}
	}

}

static int zone_purge(zone_t *zone, ctl_args_t *args)
{
	UNUSED(args);

	// Abort possible editing transaction.
	(void)zone_txn_abort(zone, args);

	// Expire the zone.
	event_expire(conf(), zone);

	// Purge the zone file.
	char *zonefile = conf_zonefile(conf(), zone->name);
	(void)unlink(zonefile);
	free(zonefile);

	// Purge the zone journal.
	char *journalfile = conf_journalfile(conf(), zone->name);
	(void)unlink(journalfile);
	free(journalfile);

	// Purge the zone timers.
	(void)remove_timer_db(args->server->timers_db, args->server->zone_db,
	                      zone->name);

	return KNOT_EOK;
}

static int ctl_zone(ctl_args_t *args, ctl_cmd_t cmd)
{
	switch (cmd) {
	case CTL_ZONE_STATUS:
		return zones_apply(args, zone_status);
	case CTL_ZONE_RELOAD:
		return zones_apply(args, zone_reload);
	case CTL_ZONE_REFRESH:
		return zones_apply(args, zone_refresh);
	case CTL_ZONE_RETRANSFER:
		return zones_apply(args, zone_retransfer);
	case CTL_ZONE_FLUSH:
		return zones_apply(args, zone_flush);
	case CTL_ZONE_SIGN:
		return zones_apply(args, zone_sign);
	case CTL_ZONE_READ:
		return zones_apply(args, zone_read);
	case CTL_ZONE_BEGIN:
		return zones_apply(args, zone_txn_begin);
	case CTL_ZONE_COMMIT:
		return zones_apply(args, zone_txn_commit);
	case CTL_ZONE_ABORT:
		return zones_apply(args, zone_txn_abort);
	case CTL_ZONE_DIFF:
		return zones_apply(args, zone_txn_diff);
	case CTL_ZONE_GET:
		return zones_apply(args, zone_txn_get);
	case CTL_ZONE_SET:
		return zones_apply(args, zone_txn_set);
	case CTL_ZONE_UNSET:
		return zones_apply(args, zone_txn_unset);
	case CTL_ZONE_PURGE:
		return zones_apply(args, zone_purge);
	default:
		assert(0);
		return KNOT_EINVAL;
	}
}

static int ctl_server(ctl_args_t *args, ctl_cmd_t cmd)
{
	int ret = KNOT_EOK;

	switch (cmd) {
	case CTL_STATUS:
		ret = KNOT_EOK;
		break;
	case CTL_STOP:
		ret = KNOT_CTL_ESTOP;
		break;
	case CTL_RELOAD:
		ret = server_reload(args->server);
		if (ret != KNOT_EOK) {
			send_error(args, knot_strerror(ret));
		}
		break;
	default:
		assert(0);
		ret = KNOT_EINVAL;
	}

	return ret;
}

static int send_block_data(conf_io_t *io, knot_ctl_data_t *data)
{
	knot_ctl_t *ctl = (knot_ctl_t *)io->misc;

	const yp_item_t *item = (io->key1 != NULL) ? io->key1 : io->key0;
	assert(item != NULL);

	char buff[YP_MAX_TXT_DATA_LEN + 1] = "\0";

	(*data)[KNOT_CTL_IDX_DATA] = buff;

	// Format explicit binary data value.
	if (io->data.bin != NULL) {
		size_t buff_len = sizeof(buff);
		int ret = yp_item_to_txt(item, io->data.bin, io->data.bin_len, buff,
		                         &buff_len, YP_SNOQUOTE);
		if (ret != KNOT_EOK) {
			return ret;
		}
		return knot_ctl_send(ctl, KNOT_CTL_TYPE_DATA, data);
	// Format all multivalued item data if no specified index.
	} else if ((item->flags & YP_FMULTI) && io->data.index == 0) {
		size_t values = conf_val_count(io->data.val);
		for (size_t i = 0; i < values; i++) {
			conf_val(io->data.val);
			size_t buff_len = sizeof(buff);
			int ret = yp_item_to_txt(item, io->data.val->data,
			                         io->data.val->len, buff,&buff_len,
			                         YP_SNOQUOTE);
			if (ret != KNOT_EOK) {
				return ret;
			}

			knot_ctl_type_t type = (i == 0) ? KNOT_CTL_TYPE_DATA :
			                                  KNOT_CTL_TYPE_EXTRA;
			ret = knot_ctl_send(ctl, type, data);
			if (ret != KNOT_EOK) {
				return ret;
			}

			conf_val_next(io->data.val);
		}
		return KNOT_EOK;
	// Format singlevalued item data or a specified one from multivalued.
	} else {
		conf_val(io->data.val);
		size_t buff_len = sizeof(buff);
		int ret = yp_item_to_txt(item, io->data.val->data, io->data.val->len,
		                         buff, &buff_len, YP_SNOQUOTE);
		if (ret != KNOT_EOK) {
			return ret;
		}
		return knot_ctl_send(ctl, KNOT_CTL_TYPE_DATA, data);
	}
}

static int send_block(conf_io_t *io)
{
	knot_ctl_t *ctl = (knot_ctl_t *)io->misc;

	// Get possible error message.
	const char *err = io->error.str;
	if (err == NULL && io->error.code != KNOT_EOK) {
		err = knot_strerror(io->error.code);
	}

	knot_ctl_data_t data = {
		[KNOT_CTL_IDX_ERROR] = err,
	};

	if (io->key0 != NULL) {
		data[KNOT_CTL_IDX_SECTION] = io->key0->name + 1;
	}
	if (io->key1 != NULL) {
		data[KNOT_CTL_IDX_ITEM] = io->key1->name + 1;
	}

	// Get the item prefix.
	switch (io->type) {
	case NEW: data[KNOT_CTL_IDX_FLAGS] = CTL_FLAG_ADD; break;
	case OLD: data[KNOT_CTL_IDX_FLAGS] = CTL_FLAG_REM; break;
	default: break;
	}

	char id[KNOT_DNAME_TXT_MAXLEN + 1] = "\0";

	// Get the textual item id.
	if (io->id_len > 0 && io->key0 != NULL) {
		size_t id_len = sizeof(id);
		int ret = yp_item_to_txt(io->key0->var.g.id, io->id, io->id_len,
		                         id, &id_len, YP_SNOQUOTE);
		if (ret != KNOT_EOK) {
			return ret;
		}
		if (io->id_as_data) {
			data[KNOT_CTL_IDX_DATA] = id;
		} else {
			data[KNOT_CTL_IDX_ID] = id;
		}
	}

	if (io->data.val == NULL && io->data.bin == NULL) {
		return knot_ctl_send(ctl, KNOT_CTL_TYPE_DATA, &data);
	} else {
		return send_block_data(io, &data);
	}
}

static int ctl_conf_txn(ctl_args_t *args, ctl_cmd_t cmd)
{
	conf_io_t io = {
		.fcn = send_block,
		.misc = args->ctl
	};

	int ret = KNOT_EOK;

	switch (cmd) {
	case CTL_CONF_BEGIN:
		ret = conf_io_begin(false);
		break;
	case CTL_CONF_ABORT:
		conf_io_abort(false);
		ret = KNOT_EOK;
		break;
	case CTL_CONF_COMMIT:
		// First check the database.
		ret = conf_io_check(&io);
		if (ret != KNOT_EOK) {
			// Error response is already sent by the check function.
			// No transaction abort!
			return KNOT_EOK;
		}

		ret = conf_io_commit(false);
		if (ret != KNOT_EOK) {
			conf_io_abort(false);
			break;
		}

		ret = server_reload(args->server);
		break;
	default:
		assert(0);
		ret = KNOT_EINVAL;
	}

	if (ret != KNOT_EOK) {
		send_error(args, knot_strerror(ret));
	}

	return ret;
}

static int ctl_conf_read(ctl_args_t *args, ctl_cmd_t cmd)
{
	conf_io_t io = {
		.fcn = send_block,
		.misc = args->ctl
	};

	int ret = KNOT_EOK;

	while (true) {
		const char *key0 = args->data[KNOT_CTL_IDX_SECTION];
		const char *key1 = args->data[KNOT_CTL_IDX_ITEM];
		const char *id   = args->data[KNOT_CTL_IDX_ID];

		switch (cmd) {
		case CTL_CONF_LIST:
			ret = conf_io_list(key0, &io);
			break;
		case CTL_CONF_READ:
			ret = conf_io_get(key0, key1, id, true, &io);
			break;
		case CTL_CONF_DIFF:
			ret = conf_io_diff(key0, key1, id, &io);
			break;
		case CTL_CONF_GET:
			ret = conf_io_get(key0, key1, id, false, &io);
			break;
		default:
			assert(0);
			ret = KNOT_EINVAL;
		}
		if (ret != KNOT_EOK) {
			send_error(args, knot_strerror(ret));
			break;
		}

		// Get next data unit.
		ret = knot_ctl_receive(args->ctl, &args->type, &args->data);
		if (ret != KNOT_EOK || args->type != KNOT_CTL_TYPE_DATA) {
			break;
		}
		ctl_log_data(&args->data);
	}

	return ret;
}

static int ctl_conf_modify(ctl_args_t *args, ctl_cmd_t cmd)
{
	// Start child transaction.
	int ret = conf_io_begin(true);
	if (ret != KNOT_EOK) {
		send_error(args, knot_strerror(ret));
		return ret;
	}

	while (true) {
		const char *key0 = args->data[KNOT_CTL_IDX_SECTION];
		const char *key1 = args->data[KNOT_CTL_IDX_ITEM];
		const char *id   = args->data[KNOT_CTL_IDX_ID];
		const char *data = args->data[KNOT_CTL_IDX_DATA];

		switch (cmd) {
		case CTL_CONF_SET:
			ret = conf_io_set(key0, key1, id, data);
			break;
		case CTL_CONF_UNSET:
			ret = conf_io_unset(key0, key1, id, data);
			break;
		default:
			assert(0);
			ret = KNOT_EINVAL;
		}
		if (ret != KNOT_EOK) {
			send_error(args, knot_strerror(ret));
			break;
		}

		// Get next data unit.
		ret = knot_ctl_receive(args->ctl, &args->type, &args->data);
		if (ret != KNOT_EOK || args->type != KNOT_CTL_TYPE_DATA) {
			break;
		}
		ctl_log_data(&args->data);
	}

	// Finish child transaction.
	if (ret == KNOT_EOK) {
		ret = conf_io_commit(true);
		if (ret != KNOT_EOK) {
			send_error(args, knot_strerror(ret));
		}
	} else {
		conf_io_abort(true);
	}

	return ret;
}

typedef struct {
	const char *name;
	int (*fcn)(ctl_args_t *, ctl_cmd_t);
} desc_t;

static const desc_t cmd_table[] = {
	[CTL_NONE]            = { "" },

	[CTL_STATUS]          = { "status",          ctl_server },
	[CTL_STOP]            = { "stop",            ctl_server },
	[CTL_RELOAD]          = { "reload",          ctl_server },

	[CTL_ZONE_STATUS]     = { "zone-status",     ctl_zone },
	[CTL_ZONE_RELOAD]     = { "zone-reload",     ctl_zone },
	[CTL_ZONE_REFRESH]    = { "zone-refresh",    ctl_zone },
	[CTL_ZONE_RETRANSFER] = { "zone-retransfer", ctl_zone },
	[CTL_ZONE_FLUSH]      = { "zone-flush",      ctl_zone },
	[CTL_ZONE_SIGN]       = { "zone-sign",       ctl_zone },

	[CTL_ZONE_READ]       = { "zone-read",       ctl_zone },
	[CTL_ZONE_BEGIN]      = { "zone-begin",      ctl_zone },
	[CTL_ZONE_COMMIT]     = { "zone-commit",     ctl_zone },
	[CTL_ZONE_ABORT]      = { "zone-abort",      ctl_zone },
	[CTL_ZONE_DIFF]       = { "zone-diff",       ctl_zone },
	[CTL_ZONE_GET]        = { "zone-get",        ctl_zone },
	[CTL_ZONE_SET]        = { "zone-set",        ctl_zone },
	[CTL_ZONE_UNSET]      = { "zone-unset",      ctl_zone },
	[CTL_ZONE_PURGE]      = { "zone-purge",      ctl_zone },

	[CTL_CONF_LIST]       = { "conf-list",       ctl_conf_read },
	[CTL_CONF_READ]       = { "conf-read",       ctl_conf_read },
	[CTL_CONF_BEGIN]      = { "conf-begin",      ctl_conf_txn },
	[CTL_CONF_COMMIT]     = { "conf-commit",     ctl_conf_txn },
	[CTL_CONF_ABORT]      = { "conf-abort",      ctl_conf_txn },
	[CTL_CONF_DIFF]       = { "conf-diff",       ctl_conf_read },
	[CTL_CONF_GET]        = { "conf-get",        ctl_conf_read },
	[CTL_CONF_SET]        = { "conf-set",        ctl_conf_modify },
	[CTL_CONF_UNSET]      = { "conf-unset",      ctl_conf_modify },
};

#define MAX_CTL_CODE (sizeof(cmd_table) / sizeof(desc_t) - 1)

const char *ctl_cmd_to_str(ctl_cmd_t cmd)
{
	if (cmd <= CTL_NONE || cmd > MAX_CTL_CODE) {
		return NULL;
	}

	return cmd_table[cmd].name;
}

ctl_cmd_t ctl_str_to_cmd(const char *cmd_str)
{
	if (cmd_str == NULL) {
		return CTL_NONE;
	}

	for (ctl_cmd_t cmd = CTL_NONE + 1; cmd <= MAX_CTL_CODE; cmd++) {
		if (strcmp(cmd_str, cmd_table[cmd].name) == 0) {
			return cmd;
		}
	}

	return CTL_NONE;
}

int ctl_exec(ctl_cmd_t cmd, ctl_args_t *args)
{
	if (args == NULL) {
		return KNOT_EINVAL;
	}

	return cmd_table[cmd].fcn(args, cmd);
}

bool ctl_has_flag(const char *flags, const char *flag)
{
	if (flags == NULL || flag == NULL) {
		return false;
	}

	return strstr(flags, flag) != NULL;
}
