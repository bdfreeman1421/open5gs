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

#include "opof_clientlib.h"
#include "opof-util.h"
#include "context.h"


#include  <string.h>

int opof_init(void)
{
	   //const char *address = ptv->openoffload_host;
	   char address[128];
	   strcpy(address,"localhost");
           unsigned short port = 3443;
           char cert[2048];
           ogs_info("Calling opof_create_sessionTable");
           sgwc_self()->opof_handle = opof_create_sessionTable(address, port, cert);
	   int status = 0 ;
           unsigned long sessionId = 0 ;
           sessionResponse_t*  opofResponse ;
           opofResponse = (sessionResponse_t *)malloc(sizeof(sessionResponse_t));
           opofResponse->sessionId = 0;
           ogs_info("Calling opof_get_session");
           status = opof_get_session(sgwc_self()->opof_handle,  sessionId , opofResponse);
	   if (status < 0) {
                ogs_error("Error Calling opof_get_session");
	   }
	   return  OGS_OK;
}


int openoffload_add_session(ogs_ip_t ue_ip, ogs_ip_t enb_gtp_ip, ogs_ip_t sgwu_gtp_ip, uint32_t enb_fteid , uint32_t spgw_teid)
{
  //  create session entry
  //  add to sessions
  //  send sessions

  ogs_info("Calling opof_add_session");
  // Check if IMSI has active GTP-C and/or GTP-U


  struct in_addr encapMatchDestinationIp ;
  encapMatchDestinationIp.s_addr = ue_ip.addr;
  //ogs_info("encapMatchestinationIp %s\n", srslte::gtpu_ntoa(encapMatchDestinationIp.s_addr).c_str());
  struct in_addr addr1;
  addr1.s_addr = encapMatchDestinationIp.s_addr;
  ogs_info("encapMatchestinationIp %s\n", inet_ntoa(addr1));


  sessionRequest_t **requests;
  sessionRequest_t *request;
  addSessionResponse_t addResp;

         unsigned int bufferSize;
        /*  set buffer size to 1
        *  TODO: pack up to 64 sessions into an addSession message
        *  SmartNIC will setup forward and reverse flows based on single session entry in request
        */
        bufferSize=1;
        unsigned long sessionId;
        // need srcLTE freiendly sessionId
        // not clear teid is appropriate
        sessionId=spgw_teid ;
        int status;
        PROTOCOL_ID_T proto;
        IP_VERSION_T ipver;
        ACTION_VALUE_T action;
        proto = _UDP;
        ipver = _IPV4;
        action = _ENCAP_DECAP;
        unsigned int timeout = 30u;
        struct in_addr srcip;
        struct in_addr dstip;
        uint   srcport;
        uint   dstport;
        struct in_addr nexthopip;
        /* TODO: should be null - setting for demonstration */
        nexthopip.s_addr= inet_addr("192.168.0.1");
        // for encap/decap should be enodeB srcip and spgw dstip
        // m_s1u_addr.sin_addr.s_addr
        //srcip.s_addr= iph->saddr;
        srcip.s_addr=enb_gtp_ip.addr;
        //srcip.s_addr= m_s1u_addr.sin_addr.s_addr;
        //dstip.s_addr= iph->daddr;
        dstip.s_addr= sgwu_gtp_ip.addr;
                // for encap/decap should be GTP port
        srcport= OGS_GTPV1_U_UDP_PORT;
        dstport= OGS_GTPV1_U_UDP_PORT;

        MATCH_TYPE_T matchType = _GTP_HEADER;
        ENCAP_TYPE_T encapType = _GTP;

	uint encapTunnelEndpointId = enb_fteid ;
        uint tunnelEndpointId = spgw_teid;


        ogs_info("srcip: %s uint:%u", inet_ntoa(srcip), srcip.s_addr);
        ogs_info("dstip: %s uint:%u", inet_ntoa(dstip), dstip.s_addr);
        ogs_info("request ipver: %u", ipver);
        ogs_info("request protcoldID: %u", proto);


        requests = (sessionRequest_t **)malloc(bufferSize * (sizeof(requests)));
	unsigned long i;
        for (i = 0; i < bufferSize; i++){
                    request = (sessionRequest_t *)malloc(sizeof(*request));
                    request->sessId = (2+sessionId);
                    // for smartnic inlif/outlif should be a config variable
                    request->inlif = 3;
                    request->outlif = 4;
                    request->srcPort = srcport;
                    request->dstPort = dstport;
                    request->proto = proto;
                    request->ipver = ipver;
                    request->nextHop = nexthopip;
                    request->actType = action;
                    request->srcIP = srcip;
                    request->dstIP = dstip;
                    request->cacheTimeout = timeout;
                    request->matchType=matchType;
                    request->encapType=encapType;
                    request->tunnelEndpointId = tunnelEndpointId;
                    request->encapTunnelEndpointId = encapTunnelEndpointId;
                    request->encapMatchDestinationIp= encapMatchDestinationIp;
                    requests[i] = request;
                    ogs_info("request session ID[%lu]: %lu", i,request->sessId);
                    ogs_info("request ipver in loop[%lu]: %i", i, request->ipver);
                    ogs_info("request srcIP in loop[%lu]: %u", i, request->srcIP.s_addr);
                    ogs_info("request timeout in loop[%lu]: %u", i, request->cacheTimeout);

		             }

         ogs_info("requests[0].ipver %i" , requests[0]->ipver);
         status = opof_add_session(bufferSize,sgwc_self()->opof_handle, requests, &addResp);
         if (status == FAILURE){
             ogs_info("ERROR: Adding offload sessions");
             ogs_error("ERROR: Adding offload sessions");
             //return FAILURE;
             return OGS_ERROR ;
         }
         if (addResp.number_errors > 0){
             ogs_info("\n\nErrors in the following sessions\n");
	     int i;
             for (i=0; i < addResp.number_errors; i++){
                 ogs_info("\tSessionId: %lu\t error: %i\n", addResp.sessionErrors[i].sessionId, addResp.sessionErrors[i].errorStatus);
             }
         }
         ogs_info("addSession number_errors: %i", addResp.number_errors);

  return  OGS_OK;
}

int  openoffload_delete_session (uint32_t session_id) 
{
  int status;
  sessionResponse_t delResp;
  status = opof_del_session(sgwc_self()->opof_handle,  session_id, &delResp);
  if (status == FAILURE){
    ogs_info("ERROR: Deleting offload session");
    ogs_error("ERROR: Deleteing offload sessions");
    return OGS_ERROR ;
  }
  ogs_info("offload.sessionCloseCode: %i" , delResp.sessionState);
  ogs_info("offload.inPackets: %li" , delResp.inPackets);
  ogs_info("offload.outPackets: %li" , delResp.outPackets);

return OGS_OK;
}
