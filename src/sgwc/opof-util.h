/*
 * Copyright (C) 2021 by AT&T Intellectual property 
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */


#include "context.h"

#define  GTPU_RX_PORT    2152
#define  GTPU_TX_PORT    2152 
// #define OGS_GTPV1_U_UDP_PORT            2152

int opof_init(void) ;
int openoffload_add_session(ogs_ip_t ue_ip, ogs_ip_t enb_gtp_ip, ogs_ip_t sgwu_gtp_ip, uint32_t enb_fteid , uint32_t spgw_teid);
int openoffload_delete_session(uint32_t session_id);
