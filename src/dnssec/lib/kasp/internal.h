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

#pragma once

#include "kasp.h"

/*!
 * Create new KASP handle.
 *
 * \param[out] kasp_ptr   New KASP handle.
 * \param[in]  functions  KASP store implementation.
 *
 * \return Error code, DNSSE_EOK if successful.
 */
int dnssec_kasp_create(dnssec_kasp_t **kasp_ptr,
		       const dnssec_kasp_store_functions_t *functions);

/*!
 * Free content of the keystore structure.
 */
void kasp_keystore_cleanup(dnssec_kasp_keystore_t *keystore);
