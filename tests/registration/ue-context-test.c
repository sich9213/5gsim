/*
 * Copyright (C) 2019,2020 by Sukchan Lee <acetcom@gmail.com>
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

#include "test-common.h"
#define THREADNUM 5 
#define CONCURRENT 1 
int rv;
ogs_socknode_t *ngap;
ogs_socknode_t *ngap2;
ogs_socknode_t *gtpu;
ogs_socknode_t *gtpu2;

ogs_pkbuf_t *sendbuf;
ogs_pkbuf_t *recvbuf;
//ogs_pkbuf_t *recvbuf_gtpu; // temp use
ogs_pkbuf_t *recvbuf_thread[5*THREADNUM]; // temp use
#include <netinet/ip_icmp.h>
struct icmp *icmp_record[5*THREADNUM]; // record every icmp for each UE
int map_ran_ue[5*THREADNUM];


// thread locks
#include <pthread.h>
#include <semaphore.h>
sem_t occupied_s1ap_read;
sem_t occupied_gtpu_read;
int all_terminated = 0;
sem_t received_sem_ue[5*THREADNUM];

// mutex for sending
pthread_mutex_t s1ap_send_lock = PTHREAD_MUTEX_INITIALIZER;

#define log_update(x,y) { x = clock()-y; y = clock(); }
#define log_reset_time(x) {x = clock();}
struct UE_LOG {
    	clock_t init_ue_msg_time;
	clock_t auth_request_time;
    	clock_t auth_response_time ;
	clock_t security_mode_command_time ;
	clock_t security_mode_complete_time ;
	clock_t ESM_info_request_time ;
	clock_t ESM_info_response_time ;
	clock_t UE_info_time ;
	clock_t initial_context_setup_receive_time;
	clock_t initial_context_setup_send_time ;
    	clock_t activate_EPS_time ;
    	clock_t receive_EMM_time ;
	clock_t EMM_service_request_time;
    	clock_t ping_time ;
	clock_t detach_request_time ;
	clock_t UE_release_command_time ;
	clock_t UE_release_complete_time ;
	clock_t last_update ;

}ue_log[5*THREADNUM];


void sock_init(char *ip_amf, char *ip_gnb) {
	
    /* gNB connects to AMF */
    //ngap = testngap_client(AF_INET);
    //ngap = testngap_client_ip(AF_INET, "127.0.0.5");
    ngap = testngap_client_ip(AF_INET, ip_amf);
    ngap2 = testngap_client_ip(AF_INET, ip_amf);

    //ABTS_PTR_NOTNULL(tc, ngap);
    /* gNB connects to UPF */
    //gtpu = test_gtpu_server(1, AF_INET);
    //gtpu = test_gtpu_server_ip(1, AF_INET, "127.0.0.2");
    gtpu = test_gtpu_server_ip(1, AF_INET, ip_gnb);
    //gtpu2 = test_gtpu_server_ip(2, AF_INET, ip_gnb);
    //ABTS_PTR_NOTNULL(tc, gtpu);

    /* Send NG-Setup Reqeust */
    sendbuf = testngap_build_ng_setup_request(0x4000, 30);
    //ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    //ABTS_INT_EQUAL(tc, OGS_OK, rv);
    
    /* Receive NG-Setup Response */
    recvbuf = testgnb_ngap_read(ngap);
    //ABTS_PTR_NOTNULL(tc, recvbuf);
    //testngap_recv(test_ue, recvbuf);

    sendbuf = testngap_build_ng_setup_request(0x4001, 28);
//    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap2, sendbuf);
//    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    recvbuf = testgnb_ngap_read(ngap2);
//    ABTS_PTR_NOTNULL(tc, recvbuf);
//    testngap_recv(test_ue, recvbuf);


}
void sock_close() {
    /* gNB disonncect from UPF */
    testgnb_gtpu_close(gtpu);

    /* gNB disonncect from AMF */
    testgnb_ngap_close(ngap);

    /* Clear Test UE Context */
    //test_ue_remove(test_ue);

}
#if 0

static void test_handover(abts_case *tc, void *data)
{
    int rv;
    ogs_pkbuf_t *gmmbuf;
    ogs_pkbuf_t *gsmbuf;
    ogs_pkbuf_t *nasbuf;
    ogs_ngap_message_t message;
    int i;

    uint8_t tmp[OGS_MAX_SDU_LEN];
    char *_gtp_payload = "34ff0024"
        "0000000100000085 010002004500001c 0c0b000040015a7a 0a2d00010a2d0002"
        "00000964cd7c291f";

    ogs_nas_5gs_mobile_identity_suci_t mobile_identity_suci;
    test_ue_t *test_ue = NULL;
    test_sess_t *sess = NULL;
    test_bearer_t *qos_flow = NULL;

    int ue_id = ((int*)data)[0];
    int imsi = 21309 + ue_id;
    long ran_ue_ngap_id = 2*ue_id;

    const char *_k_string = "70d49a71dd1a2b806a25abe0ef749f1e";
    uint8_t k[OGS_KEY_LEN];
    const char *_opc_string = "6f1bf53d624b3a43af6592854e2444c7";
    uint8_t opc[OGS_KEY_LEN];

    mongoc_collection_t *collection = NULL;
    bson_t *doc = NULL;
    int64_t count = 0;
    bson_error_t error;
    const char *json =
      "{"
        "\"_id\" : { \"$oid\" : \"597223158b8861d7605378c6\" }, "
        "\"imsi\" : \"901700000021309\","
        "\"ambr\" : { "
          "\"uplink\" : { \"$numberLong\" : \"1024000\" }, "
          "\"downlink\" : { \"$numberLong\" : \"1024000\" } "
        "},"
        "\"pdn\" : ["
          "{"
            "\"apn\" : \"internet\", "
            "\"_id\" : { \"$oid\" : \"597223158b8861d7605378c7\" }, "
            "\"ambr\" : {"
              "\"uplink\" : { \"$numberLong\" : \"1024000\" }, "
              "\"downlink\" : { \"$numberLong\" : \"1024000\" } "
            "},"
            "\"qos\" : { "
              "\"qci\" : 9, "
              "\"arp\" : { "
                "\"priority_level\" : 8,"
                "\"pre_emption_vulnerability\" : 1, "
                "\"pre_emption_capability\" : 1"
              "} "
            "}, "
            "\"type\" : 2,"
            "\"pcc_rule\" : ["
              "{"
                "\"_id\" : { \"$oid\" : \"599eb929c850caabcbfdcd2d\" },"
                "\"qos\" : {"
                  "\"qci\" : 1,"
                  "\"gbr\" : {"
                    "\"downlink\" : { \"$numberLong\" : \"64\" },"
                    "\"uplink\" : { \"$numberLong\" : \"44\" }"
                  "},"
                  "\"mbr\" : {"
                    "\"downlink\" : { \"$numberLong\" : \"64\" },"
                    "\"uplink\" : { \"$numberLong\" : \"44\" }"
                  "},"
                  "\"arp\" : {"
                    "\"priority_level\" : 3,"
                    "\"pre_emption_vulnerability\" : 0,"
                    "\"pre_emption_capability\" : 0 }"
                  "},"
                  "\"flow\" : ["
                    "{ \"direction\" : 2,"
                      "\"description\" : \"permit out udp from 10.200.136.98/32 23454 to assigned 1-65535\","
                      "\"_id\" : { \"$oid\" : \"599eb929c850caabcbfdcd31\" } },"
                    "{ \"direction\" : 1,"
                      "\"description\" : \"permit out udp from 10.200.136.98/32 1-65535 to assigned 50020\","
                      "\"_id\" : { \"$oid\" : \"599eb929c850caabcbfdcd30\" } },"
                    "{ \"direction\" : 2,"
                      "\"description\" : \"permit out udp from 10.200.136.98/32 23455 to assigned 1-65535\","
                      "\"_id\" : { \"$oid\" : \"599eb929c850caabcbfdcd2f\" } },"
                    "{ \"direction\" : 1,"
                      "\"description\" : \"permit out udp from 10.200.136.98/32 1-65535 to assigned 50021\","
                      "\"_id\" : { \"$oid\" : \"599eb929c850caabcbfdcd2e\" } }"
                  "]"
              "}"
            "]"
          "}"
        "],"
        "\"security\" : { "
          "\"k\" : \"70d49a71dd1a2b806a25abe0ef749f1e\", "
          "\"opc\" : \"6f1bf53d624b3a43af6592854e2444c7\", "
          "\"amf\" : \"8000\", "
          "\"sqn\" : { \"$numberLong\" : \"25235952177090\" } "
        "}, "
        "\"subscribed_rau_tau_timer\" : 12,"
        "\"network_access_mode\" : 2, "
        "\"subscriber_status\" : 0, "
        "\"access_restriction_data\" : 32, "
        "\"__v\" : 0 "
      "}";

    /* Setup Test UE & Session Context */
    memset(&mobile_identity_suci, 0, sizeof(mobile_identity_suci));

    mobile_identity_suci.h.supi_format = OGS_NAS_5GS_SUPI_FORMAT_IMSI;
    mobile_identity_suci.h.type = OGS_NAS_5GS_MOBILE_IDENTITY_SUCI;
    mobile_identity_suci.routing_indicator1 = 0;
    mobile_identity_suci.routing_indicator2 = 0xf;
    mobile_identity_suci.routing_indicator3 = 0xf;
    mobile_identity_suci.routing_indicator4 = 0xf;
    mobile_identity_suci.protection_scheme_id = OGS_NAS_5GS_NULL_SCHEME;
    mobile_identity_suci.home_network_pki_value = 0;
    mobile_identity_suci.scheme_output[0] = 0;
    mobile_identity_suci.scheme_output[1] = 0;
    int timsi = imsi;
    int j;
    for ( j = 4 ; j >= 2 ; --j ) { // AUTO - GENERATE NEW IMSI based on ue_id
	    mobile_identity_suci.scheme_output[j] = 0;
	    mobile_identity_suci.scheme_output[j] *= 16;
	    mobile_identity_suci.scheme_output[j] += timsi%10;
	    timsi /= 10;

	    mobile_identity_suci.scheme_output[j] *= 16;
	    mobile_identity_suci.scheme_output[j] += timsi%10;
	    timsi /= 10;
    }



    test_ue = test_ue_add_by_suci(&mobile_identity_suci, 13);
    test_ue->ran_ue_ngap_id = ran_ue_ngap_id-1; // due to decrease in testngap_build_initial_ue_message, need -1 here
    ogs_assert(test_ue);

    test_ue->nr_cgi.cell_id = 0x40001;

    test_ue->nas.registration.type = OGS_NAS_KSI_NO_KEY_IS_AVAILABLE;
    test_ue->nas.registration.follow_on_request = 1;
    test_ue->nas.registration.value = OGS_NAS_5GS_REGISTRATION_TYPE_INITIAL;

    OGS_HEX(_k_string, strlen(_k_string), test_ue->k);
    OGS_HEX(_opc_string, strlen(_opc_string), test_ue->opc);
    
    /* Send Registration request */
    pthread_mutex_lock(&s1ap_send_lock);
    test_ue->registration_request_param.guti = 1;
    gmmbuf = testgmm_build_registration_request(test_ue, NULL);
    ABTS_PTR_NOTNULL(tc, gmmbuf);

    test_ue->registration_request_param.gmm_capability = 1;
    test_ue->registration_request_param.requested_nssai = 1;
    test_ue->registration_request_param.last_visited_registered_tai = 1;
    test_ue->registration_request_param.ue_usage_setting = 1;
    nasbuf = testgmm_build_registration_request(test_ue, NULL);
    ABTS_PTR_NOTNULL(tc, nasbuf);

    sendbuf = testngap_build_initial_ue_message(test_ue, gmmbuf, false, true);
    ran_ue_ngap_id = test_ue->ran_ue_ngap_id;
    map_ran_ue[ran_ue_ngap_id] = ue_id;

    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    printf("[SEND INIT UE MSG DONE]: %d\n",ue_id);
    log_update( log->init_ue_msg_time, log->last_update );
    pthread_mutex_unlock(&s1ap_send_lock);

    /* Receive Identity request */
    /*
    recvbuf = testgnb_ngap_read(ngap1);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);*/
    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ran_ue_ngap_id]);
    testngap_recv(test_ue, recvbuf_thread[ran_ue_ngap_id]);
    ogs_pkbuf_free(recvbuf_thread[ran_ue_ngap_id]);
    printf("[Receive Identity request DONE]: %d\n", ue_id);
    log_update(log->auth_request_time, log->last_update);

    /* Send Identity response */
    pthread_mutex_lock(&s1ap_send_lock);
    gmmbuf = testgmm_build_identity_response(test_ue);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    printf("[Send Identity response DONE]: %d\n", ue_id);
    pthread_mutex_unlock(&s1ap_send_lock);

    /* Receive Authentication request */
    /*
    recvbuf = testgnb_ngap_read(ngap1);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);*/
    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ran_ue_ngap_id]);
    testngap_recv(test_ue, recvbuf_thread[ran_ue_ngap_id]);
    ogs_pkbuf_free(recvbuf_thread[ran_ue_ngap_id]);
    printf("[RECV AUTH REQUEST DONE]: %d\n", ue_id);

    /* Send Authentication response */
    pthread_mutex_lock(&s1ap_send_lock);
    gmmbuf = testgmm_build_authentication_response(test_ue);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap1, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    printf("[Send Authentication response DONE]: %d\n", ue_id);
    pthread_mutex_unlock(&s1ap_send_lock);

    /* Receive Security mode command */
    /*
    recvbuf = testgnb_ngap_read(ngap1);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);*/
    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ran_ue_ngap_id]);
    testngap_recv(test_ue, recvbuf_thread[ran_ue_ngap_id]);
    ogs_pkbuf_free(recvbuf_thread[ran_ue_ngap_id]);
    printf("[Receive Security mode command DONE]: %d\n",ue_id);

    /* Send Security mode complete */
    pthread_mutex_lock(&s1ap_send_lock);
    gmmbuf = testgmm_build_security_mode_complete(test_ue, nasbuf);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap1, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    pthread_mutex_unlock(&s1ap_send_lock);
    printf("[Send Security mode complete DONE]: %d\n",ue_id);

    /* Receive Initial context setup request +
     * Registration accept */
    /*
    recvbuf = testgnb_ngap_read(ngap1);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc,
            NGAP_ProcedureCode_id_InitialContextSetup,
            test_ue->ngap_procedure_code);*/
    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ran_ue_ngap_id]);
    testngap_recv(test_ue, recvbuf_thread[ran_ue_ngap_id]);
    ogs_pkbuf_free(recvbuf_thread[ran_ue_ngap_id]);
    printf("[Receive Initial context setup request DONE]: %d\n", ue_id);

    /* Send UE radio capability info indication */
    pthread_mutex_lock(&s1ap_send_lock);
    sendbuf = testngap_build_ue_radio_capability_info_indication(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap1, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    printf("[Send UE radio capability info indication DONE]: %d\n",ue_id);
    pthread_mutex_unlock(&s1ap_send_lock);

    /* Send Initial context setup response */
    pthread_mutex_lock(&s1ap_send_lock);
    sendbuf = testngap_build_initial_context_setup_response(test_ue, false);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap1, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    printf("[Send Initial context setup response DONE]: %d\n",ue_id);
    pthread_mutex_unlock(&s1ap_send_lock);


    /* Send Registration complete */
    pthread_mutex_lock(&s1ap_send_lock);
    gmmbuf = testgmm_build_registration_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap1, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    printf("[Send Registration complete DONE]: %d\n",ue_id);
    pthread_mutex_unlock(&s1ap_send_lock);


    /* Receive Configuration update command */
    /*
    recvbuf = testgnb_ngap_read(ngap1);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);*/
    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ran_ue_ngap_id]);
    testngap_recv(test_ue, recvbuf_thread[ran_ue_ngap_id]);
    ogs_pkbuf_free(recvbuf_thread[ran_ue_ngap_id]);
    printf("[Receive Configuration update command DONE]: %d\n", ue_id);

    /* Send PDU session establishment request */
    int psi = ue_id+1;
    pthread_mutex_lock(&s1ap_send_lock);
    sess = test_sess_add_by_dnn_and_psi(test_ue, "internet", ue_id);
    ogs_assert(sess);

    sess->ul_nas_transport_param.request_type =
        OGS_NAS_5GS_REQUEST_TYPE_INITIAL;
    sess->ul_nas_transport_param.dnn = 1;
    sess->ul_nas_transport_param.s_nssai = 1;

    gsmbuf = testgsm_build_pdu_session_establishment_request(sess);
    ABTS_PTR_NOTNULL(tc, gsmbuf);
    gmmbuf = testgmm_build_ul_nas_transport(sess,
            OGS_NAS_PAYLOAD_CONTAINER_N1_SM_INFORMATION, gsmbuf);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap1, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    pthread_mutex_unlock(&s1ap_send_lock);
    printf("[Send PDU session establishment request DONE]: %d\n",ue_id);


    /* Receive PDUSessionResourceSetupRequest +
     * DL NAS transport +
     * PDU session establishment accept */
    /*
    recvbuf = testgnb_ngap_read(ngap1);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc,
            NGAP_ProcedureCode_id_PDUSessionResourceSetup,
            test_ue->ngap_procedure_code);*/
    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ran_ue_ngap_id]);
    testngap_recv(test_ue, recvbuf_thread[ran_ue_ngap_id]);
    ogs_pkbuf_free(recvbuf_thread[ran_ue_ngap_id]);
    printf("[Receive PDUSessionResourceSetupRequest DONE]: %d\n", ue_id);

    /* Send GTP-U ICMP Packet */ /*
    qos_flow = test_qos_flow_find_by_qfi(sess, 1);
    ogs_assert(qos_flow);
    rv = test_gtpu_send_ping(gtpu1, qos_flow, TEST_PING_IPV4);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);*/

    /* Send PDUSessionResourceSetupResponse */
    pthread_mutex_lock(&s1ap_send_lock);
    sendbuf = testngap_sess_build_pdu_session_resource_setup_response(sess);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap1, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    pthread_mutex_unlock(&s1ap_send_lock);
    printf("[Send PDUSessionResourceSetupResponse DONE]: %d\n", ue_id);

    /* Receive GTP-U ICMP Packet */ /*
    recvbuf = testgnb_gtpu_read(gtpu1);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);*/

    /* Send GTP-U ICMP Packet */
    /*
    rv = test_gtpu_send_ping(gtpu1, qos_flow, TEST_PING_IPV4);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);*/

    /* Receive GTP-U ICMP Packet */ /*
    recvbuf = testgnb_gtpu_read(gtpu1);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf); */

    /* Receive PDU session modification command */
    recvbuf = testgnb_ngap_read(ngap1);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    /* Send PDU session resource modify response */
    qos_flow = test_qos_flow_find_by_qfi(sess, 2);
    ogs_assert(qos_flow);

    sendbuf = testngap_build_pdu_session_resource_modify_response(qos_flow);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap1, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Send PDU session resource modify complete */
    sess->ul_nas_transport_param.request_type =
        OGS_NAS_5GS_REQUEST_TYPE_MODIFICATION_REQUEST;
    sess->ul_nas_transport_param.dnn = 0;
    sess->ul_nas_transport_param.s_nssai = 0;

    gsmbuf = testgsm_build_pdu_session_modification_complete(sess);
    ABTS_PTR_NOTNULL(tc, gsmbuf);
    gmmbuf = testgmm_build_ul_nas_transport(sess,
            OGS_NAS_PAYLOAD_CONTAINER_N1_SM_INFORMATION, gsmbuf);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap1, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Waiting for creating dedicated QoS flow in PFCP protocol */
    ogs_msleep(100);

    /* Send GTP-U ICMP Packet */
    rv = test_gtpu_send_ping(gtpu1, qos_flow, TEST_PING_IPV4);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive GTP-U ICMP Packet */
    recvbuf = testgnb_gtpu_read(gtpu1);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);

    /* Send Path Switch Request */
    test_ue->nr_cgi.cell_id = 0x40002;
    test_ue->ran_ue_ngap_id++;
    sess->gnb_n3_addr = test_self()->gnb2_addr;

    sendbuf = testngap_build_path_switch_request(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap2, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive End Mark */
    recvbuf = test_gtpu_read(gtpu1);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);

    /* Receive End Mark */
    recvbuf = test_gtpu_read(gtpu1);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);

    /* Receive Path Switch Ack */
    recvbuf = testgnb_ngap_read(ngap2);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    /* Send GTP-U ICMP Packet */
    qos_flow = test_qos_flow_find_by_qfi(sess, 1);
    ogs_assert(qos_flow);
    rv = test_gtpu_send_ping(gtpu2, qos_flow, TEST_PING_IPV4);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive GTP-U ICMP Packet */
    recvbuf = testgnb_gtpu_read(gtpu2);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);

    /* Send GTP-U ICMP Packet */
    qos_flow = test_qos_flow_find_by_qfi(sess, 2);
    ogs_assert(qos_flow);
    rv = test_gtpu_send_ping(gtpu2, qos_flow, TEST_PING_IPV4);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive GTP-U ICMP Packet */
    recvbuf = testgnb_gtpu_read(gtpu2);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);

    /* Send Path Switch Request */
    test_ue->nr_cgi.cell_id = 0x40001;
    test_ue->ran_ue_ngap_id++;
    sess->gnb_n3_addr = test_self()->gnb1_addr;

    sendbuf = testngap_build_path_switch_request(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap1, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive End Mark */
    recvbuf = test_gtpu_read(gtpu2);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);

    /* Receive End Mark */
    recvbuf = test_gtpu_read(gtpu2);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);

    /* Receive Path Switch Ack */
    recvbuf = testgnb_ngap_read(ngap1);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    /* Send GTP-U ICMP Packet */
    qos_flow = test_qos_flow_find_by_qfi(sess, 1);
    ogs_assert(qos_flow);
    rv = test_gtpu_send_ping(gtpu1, qos_flow, TEST_PING_IPV4);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive GTP-U ICMP Packet */
    recvbuf = testgnb_gtpu_read(gtpu1);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);

    /* Send GTP-U ICMP Packet */
    qos_flow = test_qos_flow_find_by_qfi(sess, 2);
    ogs_assert(qos_flow);
    rv = test_gtpu_send_ping(gtpu1, qos_flow, TEST_PING_IPV4);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive GTP-U ICMP Packet */
    recvbuf = testgnb_gtpu_read(gtpu1);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);

    /* Send UE context release request */
    sendbuf = testngap_build_ue_context_release_request(test_ue,
            NGAP_Cause_PR_radioNetwork, NGAP_CauseRadioNetwork_user_inactivity,
            true);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap1, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive UE context release command */
    recvbuf = testgnb_ngap_read(ngap1);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    /* Send UE context release complete */
    sendbuf = testngap_build_ue_context_release_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap1, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    ogs_msleep(300);

    /********** Remove Subscriber in Database */
    doc = BCON_NEW("imsi", BCON_UTF8(test_ue->imsi));
    ABTS_PTR_NOTNULL(tc, doc);
    ABTS_TRUE(tc, mongoc_collection_remove(collection,
            MONGOC_REMOVE_SINGLE_REMOVE, doc, NULL, &error))
    bson_destroy(doc);

    mongoc_collection_destroy(collection);

    /* Two gNB disonncect from UPF */
    testgnb_gtpu_close(gtpu1);
    //testgnb_gtpu_close(gtpu2);

    /* Two gNB disonncect from AMF */
    testgnb_ngap_close(ngap1);
    testgnb_ngap_close(ngap2);

    /* Clear Test UE Context */
    test_ue_remove(test_ue);
}
#endif

static void test_icmp_func(abts_case *tc, void *data)
{
    int rv;
    ogs_pkbuf_t *gmmbuf;
    ogs_pkbuf_t *gsmbuf;
    ogs_pkbuf_t *nasbuf;
    ogs_ngap_message_t message;
    int i;

    ogs_nas_5gs_mobile_identity_suci_t mobile_identity_suci;
    test_ue_t *test_ue = NULL;
    test_sess_t *sess = NULL;
    test_bearer_t *qos_flow = NULL;

    int ue_id = ((int*)data)[0];
    if ( ue_id < 0 || ue_id > 10000 ) { printf("ue_id out of range: %d\n", ue_id); return; }

    const char *_k_string = "70d49a71dd1a2b806a25abe0ef749f1e";
    uint8_t k[OGS_KEY_LEN];
    const char *_opc_string = "6f1bf53d624b3a43af6592854e2444c7";
    uint8_t opc[OGS_KEY_LEN];

    mongoc_collection_t *collection = NULL;
    bson_t *doc = NULL;
    int64_t count = 0;
    bson_error_t error;

    int imsi = 21309 + ue_id;
    long ran_ue_ngap_id = 2*ue_id;


    /* Setup Test UE & Session Context */
    memset(&mobile_identity_suci, 0, sizeof(mobile_identity_suci));

    mobile_identity_suci.h.supi_format = OGS_NAS_5GS_SUPI_FORMAT_IMSI;
    mobile_identity_suci.h.type = OGS_NAS_5GS_MOBILE_IDENTITY_SUCI;
    mobile_identity_suci.routing_indicator1 = 0;
    mobile_identity_suci.routing_indicator2 = 0xf;
    mobile_identity_suci.routing_indicator3 = 0xf;
    mobile_identity_suci.routing_indicator4 = 0xf;
    mobile_identity_suci.protection_scheme_id = OGS_NAS_5GS_NULL_SCHEME;
    mobile_identity_suci.home_network_pki_value = 0;
    mobile_identity_suci.scheme_output[0] = 0;
    mobile_identity_suci.scheme_output[1] = 0;

    int timsi = imsi;
    int j;
    //printf("timsi: %d\n",timsi);
    for ( j = 4 ; j >= 2 ; --j ) { // AUTO - GENERATE NEW IMSI based on ue_id
	    mobile_identity_suci.scheme_output[j] = 0;
	    mobile_identity_suci.scheme_output[j] *= 16;
	    mobile_identity_suci.scheme_output[j] += timsi%10;
	    timsi /= 10;

	    mobile_identity_suci.scheme_output[j] *= 16;
	    mobile_identity_suci.scheme_output[j] += timsi%10;
	    timsi /= 10;
    }


    test_ue = test_ue_add_by_suci(&mobile_identity_suci, 13);
    test_ue->ran_ue_ngap_id = ran_ue_ngap_id-1; // due to decrease in testngap_build_initial_ue_message, need -1 here
    ogs_assert(test_ue);

    test_ue->nr_cgi.cell_id = 0x40001;

    test_ue->nas.registration.type = OGS_NAS_KSI_NO_KEY_IS_AVAILABLE;
    test_ue->nas.registration.follow_on_request = 1;
    test_ue->nas.registration.value = OGS_NAS_5GS_REGISTRATION_TYPE_INITIAL;

    OGS_HEX(_k_string, strlen(_k_string), test_ue->k);
    OGS_HEX(_opc_string, strlen(_opc_string), test_ue->opc);

    struct UE_LOG *log = &ue_log[ue_id];
    log_reset_time(log->last_update);

    /* Send Registration request */
    gmmbuf = testgmm_build_registration_request(test_ue, NULL);
    ABTS_PTR_NOTNULL(tc, gmmbuf);

    test_ue->registration_request_param.gmm_capability = 1;
    test_ue->registration_request_param.requested_nssai = 1;
    test_ue->registration_request_param.last_visited_registered_tai = 1;
    test_ue->registration_request_param.ue_usage_setting = 1;
    nasbuf = testgmm_build_registration_request(test_ue, NULL);
    ABTS_PTR_NOTNULL(tc, nasbuf);

    pthread_mutex_lock(&s1ap_send_lock);
    sendbuf = testngap_build_initial_ue_message(test_ue, gmmbuf, false, true);
    ran_ue_ngap_id = test_ue->ran_ue_ngap_id;
    map_ran_ue[ran_ue_ngap_id] = ue_id;

    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    printf("[SEND INIT UE MSG DONE]: %d\n",ue_id);
    log_update( log->init_ue_msg_time, log->last_update );
    pthread_mutex_unlock(&s1ap_send_lock);

    /* Receive Authentication request */
    /*
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    */
    printf("[RECV AUTH REQUEST DONE]: %d\n", ue_id);
    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ue_id]);
    testngap_recv(test_ue, recvbuf_thread[ue_id]);
    ogs_pkbuf_free(recvbuf_thread[ue_id]);
    printf("[RECV AUTH REQUEST DONE]: %d\n", ue_id);
    log_update(log->auth_request_time, log->last_update);

    /* Send Authentication response */
    pthread_mutex_lock(&s1ap_send_lock);
    gmmbuf = testgmm_build_authentication_response(test_ue);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    pthread_mutex_unlock(&s1ap_send_lock);
    printf("[SEND AUTH RESPONSE DONE]: %d\n",ue_id);
    log_update( log->auth_response_time, log->last_update);

    /* Receive Security mode command */
    /*
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    */
    printf("[RECV SECURITY MODE DONE]: %d\n", ue_id);
    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ue_id]);
    testngap_recv(test_ue, recvbuf_thread[ue_id]);
    ogs_pkbuf_free(recvbuf_thread[ue_id]);
    printf("[RECV SECURITY MODE DONE]: %d\n", ue_id);
    log_update( log->security_mode_command_time, log->last_update);

    /* Send Security mode complete */
    pthread_mutex_lock(&s1ap_send_lock);
    gmmbuf = testgmm_build_security_mode_complete(test_ue, nasbuf);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    pthread_mutex_unlock(&s1ap_send_lock);
    printf("[SEND SECURITY MODE DONE]: %d\n",ue_id);
    log_update(log->security_mode_complete_time, log->last_update);

    /* Receive InitialContextSetupRequest +
     * Registration accept */
    /*
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc,
            NGAP_ProcedureCode_id_InitialContextSetup,
            test_ue->ngap_procedure_code);
	    */
    printf("[RECV INITIAL CONTEXT SETUP DONE]: %d\n", ue_id);
    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ue_id]);
    testngap_recv(test_ue, recvbuf_thread[ue_id]);
    ogs_pkbuf_free(recvbuf_thread[ue_id]);
    printf("[RECV INITIAL CONTEXT SETUP DONE]: %d\n", ue_id);
    log_update( log->initial_context_setup_receive_time, log->last_update);

    /* Send Registration request */
    test_ue->registration_request_param.guti = 1;
    gmmbuf = testgmm_build_registration_request(test_ue, NULL);
    ABTS_PTR_NOTNULL(tc, gmmbuf);

    test_ue->registration_request_param.gmm_capability = 1;
    test_ue->registration_request_param.requested_nssai = 1;
    test_ue->registration_request_param.last_visited_registered_tai = 1;
    test_ue->registration_request_param.ue_usage_setting = 1;
    nasbuf = testgmm_build_registration_request(test_ue, NULL);
    ABTS_PTR_NOTNULL(tc, nasbuf);

    pthread_mutex_lock(&s1ap_send_lock);
    sendbuf = testngap_build_initial_ue_message(test_ue, gmmbuf, false, true);
    ran_ue_ngap_id = test_ue->ran_ue_ngap_id;
    map_ran_ue[ran_ue_ngap_id] = ue_id;
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    printf("[SEND REGISTRATION REQUEST DONE]: %d\n",ue_id);
    log_update( log->init_ue_msg_time, log->last_update );
    //printf("ran_ue_ngap_id: %d\n",test_ue->ran_ue_ngap_id);
    pthread_mutex_unlock(&s1ap_send_lock);

    /* OLD Receive UEContextReleaseCommand */
    /*
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc,
            NGAP_ProcedureCode_id_UEContextRelease,
            test_ue->ngap_procedure_code);*/
    printf("[RECV OLD UE CONTEXT RELEASE COMMAND DONE]: %d\n",ue_id);
    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ue_id]);
    testngap_recv(test_ue, recvbuf_thread[ue_id]);
    ogs_pkbuf_free(recvbuf_thread[ue_id]);
    printf("[RECV OLD UE CONTEXT RELEASE COMMAND DONE]: %d\n",ue_id);

    /* Send OLD UE Context Release Complete */
    pthread_mutex_lock(&s1ap_send_lock);
    sendbuf = testngap_build_ue_context_release_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    printf("[SEND OLD UE CONTEXT RELEASE COMPLETE DONE]: %d\n",ue_id);
    pthread_mutex_unlock(&s1ap_send_lock);

    /* Receive Authentication request */
    /*
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf); */
    printf("[RECV AUTH REQUEST DONE]: %d\n", ue_id);
    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ue_id]);
    testngap_recv(test_ue, recvbuf_thread[ue_id]);
    ogs_pkbuf_free(recvbuf_thread[ue_id]);
    printf("[RECV AUTH REQUEST DONE]: %d\n", ue_id);

    /* Send Authentication response */
    pthread_mutex_lock(&s1ap_send_lock);
    gmmbuf = testgmm_build_authentication_response(test_ue);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    pthread_mutex_unlock(&s1ap_send_lock);
    printf("[SEND AUTH RESPONSE DONE]: %d\n",ue_id);

    /* Receive Security mode command */
    /*recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);*/
    printf("[RECV SECURITY MODE DONE]: %d\n", ue_id);
    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ue_id]);
    testngap_recv(test_ue, recvbuf_thread[ue_id]);
    ogs_pkbuf_free(recvbuf_thread[ue_id]);
    printf("[RECV SECURITY MODE DONE]: %d\n", ue_id);

    /* Send Security mode complete */
    pthread_mutex_lock(&s1ap_send_lock);
    gmmbuf = testgmm_build_security_mode_complete(test_ue, nasbuf);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    pthread_mutex_unlock(&s1ap_send_lock);
    printf("[SEND SECURITY MODE DONE]: %d\n",ue_id);

    /* Receive InitialContextSetupRequest +
     * Registration accept */
    /*recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc,
            NGAP_ProcedureCode_id_InitialContextSetup,
            test_ue->ngap_procedure_code);*/
    printf("[RECV REGISTRATION ACCEPT]: %d\n", ue_id);
    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ue_id]);
    testngap_recv(test_ue, recvbuf_thread[ue_id]);
    ogs_pkbuf_free(recvbuf_thread[ue_id]);
    printf("[RECV REGISTRATION ACCEPT]: %d\n",ue_id);

    /* Send InitialContextSetupResponse */
    pthread_mutex_lock(&s1ap_send_lock);
    sendbuf = testngap_build_initial_context_setup_response(test_ue, false);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    pthread_mutex_unlock(&s1ap_send_lock);
    printf("[SEND INIT CONTEXT SETUP RESPONSE DONE]: %d\n",ue_id);


    /* GUTI Not Present
     * SKIP Send Registration complete */
    /* SKIP Receive Configuration update command */

    /* Send PDU session establishment request */
    int psi = ue_id+1;
    sess = test_sess_add_by_dnn_and_psi(test_ue, "internet", psi);

    ogs_assert(sess);

    sess->ul_nas_transport_param.request_type =
        OGS_NAS_5GS_REQUEST_TYPE_INITIAL;
    sess->ul_nas_transport_param.dnn = 1;
    sess->ul_nas_transport_param.s_nssai = 1;
    pthread_mutex_lock(&s1ap_send_lock);
    gsmbuf = testgsm_build_pdu_session_establishment_request(sess);
    ABTS_PTR_NOTNULL(tc, gsmbuf);
    gmmbuf = testgmm_build_ul_nas_transport(sess,
            OGS_NAS_PAYLOAD_CONTAINER_N1_SM_INFORMATION, gsmbuf);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    printf("[SEND PDU SESION EST REQUEST DONE]: %d\n",ue_id);
    pthread_mutex_unlock(&s1ap_send_lock);

    /* Receive PDUSessionResourceSetupRequest +
     * DL NAS transport +
     * PDU session establishment accept */
    /*recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc,
            NGAP_ProcedureCode_id_PDUSessionResourceSetup,
            test_ue->ngap_procedure_code);*/
    printf("[RECV PDU SETUP REQUEST DONE]: %d\n", ue_id);
    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ue_id]);
    testngap_recv(test_ue, recvbuf_thread[ue_id]);
    ogs_pkbuf_free(recvbuf_thread[ue_id]);
    printf("[RECV PDU SETUP REQUEST DONE]: %d\n",ue_id);


    /* Send PDUSessionResourceSetupResponse */
    pthread_mutex_lock(&s1ap_send_lock);
    sendbuf = testngap_sess_build_pdu_session_resource_setup_response(sess);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    pthread_mutex_unlock(&s1ap_send_lock);
    printf("[SEND PDU SETUP RESPONSE DONE]: %d\n",ue_id);

    /* Send GTP-U ICMP Packet */
    pthread_mutex_lock(&s1ap_send_lock);
    qos_flow = test_qos_flow_find_by_qfi(sess, 1);
    ogs_assert(qos_flow);

    printf("destination ip is: %s\n",TEST_PING_IPV4);
    rv = test_gtpu_send_ping_2(gtpu, qos_flow, TEST_PING_IPV4, icmp_record[ue_id]);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    pthread_mutex_unlock(&s1ap_send_lock);
    printf("[SEND GTP ICMP DONE]: %d\n",ue_id);

    /* Receive GTP-U ICMP Packet */
    /*
    recvbuf = testgnb_gtpu_read(gtpu);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);*/
    sem_post(&occupied_gtpu_read);
    sem_wait(&received_sem_ue[ue_id]);
    printf("[Receive GTP-U ICMP Packet DONE]: %d\n",ue_id);


    //ogs_msleep(300);

    /* Send Initial context setup failure */
        pthread_mutex_lock(&s1ap_send_lock);
    sendbuf = testngap_build_initial_context_setup_failure(test_ue,
            NGAP_Cause_PR_radioNetwork,
            NGAP_CauseRadioNetwork_radio_connection_with_ue_lost);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    pthread_mutex_unlock(&s1ap_send_lock);
    printf("[SEND INITIAL CONTEXT SETUP FAILURE DONE]: %d\n",ue_id);

    /* Receive UEContextReleaseCommand */
    /*recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc,
            NGAP_ProcedureCode_id_UEContextRelease,
            test_ue->ngap_procedure_code);*/
    printf("[Receive UEContextReleaseCommand DONE]: %d\n",ue_id);
    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ue_id]);
    testngap_recv(test_ue, recvbuf_thread[ue_id]);
    ogs_pkbuf_free(recvbuf_thread[ue_id]);
    printf("[Receive UEContextReleaseCommand DONE]: %d\n",ue_id);


    /* Send UEContextReleaseComplete */
    pthread_mutex_lock(&s1ap_send_lock);
    sendbuf = testngap_build_ue_context_release_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    pthread_mutex_unlock(&s1ap_send_lock);
    printf("[SEND UE CONTEXT RELEASE DONE]: %d\n",ue_id);

    /* Clear Test UE Context */
    pthread_mutex_lock(&s1ap_send_lock);
    test_ue_remove(test_ue);
    pthread_mutex_unlock(&s1ap_send_lock);
}

static void test_registration_func(abts_case *tc, void *data)
{
	ogs_pkbuf_t *gmmbuf;
	ogs_pkbuf_t *gsmbuf;
	ogs_pkbuf_t *nasbuf;

	ogs_nas_5gs_mobile_identity_suci_t mobile_identity_suci;
	test_ue_t *test_ue = NULL;
	test_sess_t *sess = NULL;
	test_bearer_t *qos_flow = NULL;


	int ue_id = ((int*)data)[0];
	if ( ue_id < 0 || ue_id > 10000 ) { printf("ue_id out of range: %d\n", ue_id); return; }
	//printf("ue_id: %d\n",ue_id);
   int i;
    const char *_k_string = "70d49a71dd1a2b806a25abe0ef749f1e";
    uint8_t k[OGS_KEY_LEN];
    const char *_opc_string = "6f1bf53d624b3a43af6592854e2444c7";
    uint8_t opc[OGS_KEY_LEN];

    mongoc_collection_t *collection = NULL;
    bson_t *doc = NULL;
    int64_t count = 0;
    bson_error_t error;

    int imsi = 21309 + ue_id;
    long ran_ue_ngap_id = ue_id;

    const char *json =
      "{"
        "\"_id\" : { \"$oid\" : \"597223158b8861d7605378c6\" }, "
        "\"imsi\" : \"901700000021309\","
        "\"ambr\" : { "
          "\"uplink\" : { \"$numberLong\" : \"1024000\" }, "
          "\"downlink\" : { \"$numberLong\" : \"1024000\" } "
        "},"
        "\"pdn\" : ["
          "{"
            "\"apn\" : \"internet\", "
            "\"_id\" : { \"$oid\" : \"597223158b8861d7605378c7\" }, "
            "\"ambr\" : {"
              "\"uplink\" : { \"$numberLong\" : \"1024000\" }, "
              "\"downlink\" : { \"$numberLong\" : \"1024000\" } "
            "},"
            "\"qos\" : { "
              "\"qci\" : 9, "
              "\"arp\" : { "
                "\"priority_level\" : 8,"
                "\"pre_emption_vulnerability\" : 1, "
                "\"pre_emption_capability\" : 1"
              "} "
            "}, "
            "\"type\" : 2"
          "}"
        "],"
        "\"security\" : { "
          "\"k\" : \"70d49a71dd1a2b806a25abe0ef749f1e\", "
          "\"opc\" : \"6f1bf53d624b3a43af6592854e2444c7\", "
          "\"amf\" : \"8000\", "
          "\"sqn\" : { \"$numberLong\" : \"25235952177090\" } "
        "}, "
        "\"subscribed_rau_tau_timer\" : 12,"
        "\"network_access_mode\" : 2, "
        "\"subscriber_status\" : 0, "
        "\"access_restriction_data\" : 32, "
        "\"__v\" : 0 "
      "}";

    /* Setup Test UE & Session Context */
    memset(&mobile_identity_suci, 0, sizeof(mobile_identity_suci));

    mobile_identity_suci.h.supi_format = OGS_NAS_5GS_SUPI_FORMAT_IMSI;
    mobile_identity_suci.h.type = OGS_NAS_5GS_MOBILE_IDENTITY_SUCI;
    mobile_identity_suci.routing_indicator1 = 0;
    mobile_identity_suci.routing_indicator2 = 0xf;
    mobile_identity_suci.routing_indicator3 = 0xf;
    mobile_identity_suci.routing_indicator4 = 0xf;
    mobile_identity_suci.protection_scheme_id = OGS_NAS_5GS_NULL_SCHEME;
    mobile_identity_suci.home_network_pki_value = 0;
    mobile_identity_suci.scheme_output[0] = 0x0;
    mobile_identity_suci.scheme_output[1] = 0x0;
    //mobile_identity_suci.scheme_output[2] = 0x20;
    //mobile_identity_suci.scheme_output[3] = 0x31;
    //mobile_identity_suci.scheme_output[4] = 0x90;

    int timsi = imsi;
    int j;
    //printf("timsi: %d\n",timsi); 
    for ( j = 4 ; j >= 2 ; --j ) { // AUTO - GENERATE NEW IMSI based on ue_id
	    mobile_identity_suci.scheme_output[j] = 0;
	    mobile_identity_suci.scheme_output[j] *= 16;
	    mobile_identity_suci.scheme_output[j] += timsi%10;
	    timsi /= 10;

	    mobile_identity_suci.scheme_output[j] *= 16;
	    mobile_identity_suci.scheme_output[j] += timsi%10;
	    timsi /= 10;
    }


    test_ue = test_ue_add_by_suci(&mobile_identity_suci, 13);
    test_ue->ran_ue_ngap_id = ran_ue_ngap_id;
    ogs_assert(test_ue);

    test_ue->nr_cgi.cell_id = 0x40001;

    test_ue->nas.registration.type = OGS_NAS_KSI_NO_KEY_IS_AVAILABLE;
    test_ue->nas.registration.follow_on_request = 1;
    test_ue->nas.registration.value = OGS_NAS_5GS_REGISTRATION_TYPE_INITIAL;

    OGS_HEX(_k_string, strlen(_k_string), test_ue->k);
    OGS_HEX(_opc_string, strlen(_opc_string), test_ue->opc);

    sess = test_sess_add_by_dnn_and_psi(test_ue, "internet", 5);
    ogs_assert(sess);

    /********** Insert Subscriber in Database */
    /*
    collection = mongoc_client_get_collection(
        ogs_mongoc()->client, ogs_mongoc()->name, "subscribers");
    printf("DB NAME: %s\n",ogs_mongoc()->name);
    ABTS_PTR_NOTNULL(tc, collection);
    doc = BCON_NEW("imsi", BCON_UTF8(test_ue->imsi));

    printf("imsi: %s\n",test_ue->imsi);
    printf("ran_ue_ngap_id: %d\n",test_ue->ran_ue_ngap_id);

    ABTS_PTR_NOTNULL(tc, doc);

    count = mongoc_collection_count (
        collection, MONGOC_QUERY_NONE, doc, 0, 0, NULL, &error);
    if (count) {
        ABTS_TRUE(tc, mongoc_collection_remove(collection,
                MONGOC_REMOVE_SINGLE_REMOVE, doc, NULL, &error))
    }
    bson_destroy(doc);

    doc = bson_new_from_json((const uint8_t *)json, -1, &error);;
    ABTS_PTR_NOTNULL(tc, doc);
    ABTS_TRUE(tc, mongoc_collection_insert(collection,
                MONGOC_INSERT_NONE, doc, NULL, &error));
    bson_destroy(doc);

    doc = BCON_NEW("imsi", BCON_UTF8(test_ue->imsi));
    printf("ran_ue_ngap_id: %d\n",test_ue->ran_ue_ngap_id);
    ABTS_PTR_NOTNULL(tc, doc);
    do {
        count = mongoc_collection_count (
            collection, MONGOC_QUERY_NONE, doc, 0, 0, NULL, &error);
    } while (count == 0);
    bson_destroy(doc);
    */

    struct UE_LOG *log = &ue_log[ue_id];
    log_reset_time(log->last_update);

    /* Send Registration request */
    gmmbuf = testgmm_build_registration_request(test_ue, NULL);
    //printf("ran_ue_ngap_id: %d\n",test_ue->ran_ue_ngap_id);
    ABTS_PTR_NOTNULL(tc, gmmbuf);

    test_ue->registration_request_param.gmm_capability = 1;
    test_ue->registration_request_param.requested_nssai = 1;
    test_ue->registration_request_param.last_visited_registered_tai = 1;
    test_ue->registration_request_param.ue_usage_setting = 1;
    nasbuf = testgmm_build_registration_request(test_ue, NULL);
    //printf("ran_ue_ngap_id: %d\n",test_ue->ran_ue_ngap_id);
    ABTS_PTR_NOTNULL(tc, nasbuf);

    pthread_mutex_lock(&s1ap_send_lock);
    test_ue->ran_ue_ngap_id --; // Due to it been increased inside below function call
    sendbuf = testngap_build_initial_ue_message(test_ue, gmmbuf, false, true);
    ran_ue_ngap_id = test_ue->ran_ue_ngap_id;
    map_ran_ue[ran_ue_ngap_id] = ue_id;

    //printf("ran_ue_ngap_id: %d\n",test_ue->ran_ue_ngap_id);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
printf("[SEND INIT UE MSG DONE]: %d\n",ue_id);
log_update( log->init_ue_msg_time, log->last_update );
    //printf("ran_ue_ngap_id: %d\n",test_ue->ran_ue_ngap_id);
    pthread_mutex_unlock(&s1ap_send_lock);
    
    /* Receive Authentication request */
/*
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);  
    */
    printf("[RECV AUTH REQUEST DONE]: %d\n", ue_id);
    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ue_id]);
    testngap_recv(test_ue, recvbuf_thread[ue_id]);
    ogs_pkbuf_free(recvbuf_thread[ue_id]);
    printf("[RECV AUTH REQUEST DONE]: %d\n", ue_id);
    log_update(log->auth_request_time, log->last_update);

    /* Send Authentication response */
    pthread_mutex_lock(&s1ap_send_lock);
    gmmbuf = testgmm_build_authentication_response(test_ue);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    pthread_mutex_unlock(&s1ap_send_lock);

printf("[SEND AUTH RESPONSE DONE]: %d\n",ue_id);
log_update( log->auth_response_time, log->last_update);
    /* Receive Security mode command */
/*
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    */
    printf("[RECV SECURITY MODE DONE]: %d\n", ue_id);
    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ue_id]);
    testngap_recv(test_ue, recvbuf_thread[ue_id]);
    ogs_pkbuf_free(recvbuf_thread[ue_id]);
    printf("[RECV SECURITY MODE DONE]: %d\n", ue_id);
    log_update( log->security_mode_command_time, log->last_update);

    /* Send Security mode complete */
    pthread_mutex_lock(&s1ap_send_lock);
    gmmbuf = testgmm_build_security_mode_complete(test_ue, nasbuf);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    pthread_mutex_unlock(&s1ap_send_lock);

printf("[SEND SECURITY MODE DONE]: %d\n",ue_id);
log_update(log->security_mode_complete_time, log->last_update);

    /* Receive Initial context setup request */
/*
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    */
    printf("[RECV INITIAL CONTEXT SETUP DONE]: %d\n", ue_id);
    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ue_id]);
    testngap_recv(test_ue, recvbuf_thread[ue_id]);
    ogs_pkbuf_free(recvbuf_thread[ue_id]);
    printf("[RECV INITIAL CONTEXT SETUP DONE]: %d\n", ue_id);
    log_update( log->initial_context_setup_receive_time, log->last_update);


    /* Send Initial context setup failure */
    pthread_mutex_lock(&s1ap_send_lock);
    sendbuf = testngap_build_initial_context_setup_failure(test_ue,
            NGAP_Cause_PR_radioNetwork,
            NGAP_CauseRadioNetwork_radio_connection_with_ue_lost);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    pthread_mutex_unlock(&s1ap_send_lock);

printf("[SEND INITIAL CONTEXT SETUP FAILURE DONE]: %d\n",ue_id);
log_update( log->initial_context_setup_send_time, log->last_update);
    /* Receive UE context release command */
/*
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    */
    printf("[RECV UE CONTEXT RELEASE DONE]: %d\n", ue_id);
    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ue_id]);
    testngap_recv(test_ue, recvbuf_thread[ue_id]);
    ogs_pkbuf_free(recvbuf_thread[ue_id]);
    printf("[RECV UE CONTEXT RELEASE DONE]: %d\n", ue_id);

    /* Send UE context release complete */
    pthread_mutex_lock(&s1ap_send_lock);
    sendbuf = testngap_build_ue_context_release_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    pthread_mutex_unlock(&s1ap_send_lock);

printf("[SEND UE CONTEXT RELEASE DONE]: %d\n",ue_id);
log_update( log->UE_release_complete_time, log->last_update);
    /********** Remove Subscriber in Database */
/*
    doc = BCON_NEW("imsi", BCON_UTF8(test_ue->imsi));
    ABTS_PTR_NOTNULL(tc, doc);
    ABTS_TRUE(tc, mongoc_collection_remove(collection,
            MONGOC_REMOVE_SINGLE_REMOVE, doc, NULL, &error))
    bson_destroy(doc);

    mongoc_collection_destroy(collection);
    */

}
int buf_seq = 0 ;

int get_ran_ue_ngap_id(ogs_pkbuf_t *pkbuf) {
	test_ue_t temp_ue;
	return testngap_get_ran_ue_ngap_id(&temp_ue, pkbuf);
	//return temp_ue.ran_ue_ngap_id;
}
void *thread_gtpu_read(void *arg) {
	ogs_gtp_header_t *gtp_h = NULL;
	int rc;
	int i;
	__uint32_t teid, teid_reversed;

    	//signal(SIGINT, hsignal);
	
	while(1) {
		sem_wait(&occupied_gtpu_read);
		if ( all_terminated )
			return NULL;
/*
		recvbuf_gtpu = pkbuf_alloc(0, 200 enough for ICMP);
		rc = 0;
		while(1) {
			rc = core_recv(gtpu_sock1, recvbuf_gtpu->payload, recvbuf_gtpu->len, 0);
			if ( rc == -2 ) continue;
			else if ( rc <= 0 ) {
				if ( errno == EAGAIN) continue;
				break;
			}
			else break;
		}
		*/
		fprintf(stderr, "BEFORE\n");
		recvbuf = testgnb_gtpu_read(gtpu);
		fprintf(stderr, "AFTER\n");
		//recvbuf_gtpu->len = rc;
		/*
		gtp_h = (ogs_gtp_header_t*) recvbuf->data;

		teid_reversed = gtp_h->teid;
		teid = 0;
		while(teid_reversed) {
			teid = (teid<<8)+(teid_reversed&(0xff));
			teid_reversed>>=8;
		}
		for ( i = 0 ; i < THREADNUM ; ++i )
			if ( ue_teid[i] == teid ) break;
		if ( i == THREADNUM ) {
			fprintf(stderr,"ERROR: no thread found for teid %d\n",teid);
			fprintf(stderr,"len: %d\n",recvbuf->len);
			for ( i = 0 ; i < recvbuf->len ; ++i )
				fprintf(stderr,"%x ",*(char*)(recvbuf->data+i));
			fprintf(stderr,"\n");
			ogs_pkbuf_free(recvbuf);
			continue;
		}
		*/
		struct icmp* icmp_ptr = (struct icmp*) (recvbuf->data + recvbuf->len - 8);

		for ( i = 0 ; i < 2*THREADNUM ; ++i )
			if ( icmp_ptr->icmp_id ==  icmp_record[i]->icmp_id && icmp_ptr->icmp_seq == icmp_record[i]->icmp_seq) break;
		if ( i == 2*THREADNUM ) {
			fprintf(stderr,"ERROR: no thread found for icmp\n");
			fprintf(stderr, "id = %x\n",icmp_ptr->icmp_id);
                        fprintf(stderr, "seq = %x\n",icmp_ptr->icmp_seq);
                        ogs_pkbuf_free(recvbuf);
                        continue;
		}
		else {
			fprintf(stderr,"thread found for icmp\n");
			fprintf(stderr, "id = %x\n",icmp_ptr->icmp_id);
                        fprintf(stderr, "seq = %x\n",icmp_ptr->icmp_seq);
		}
		fprintf(stderr, "gtpu reader found id %d\n",i);

		recvbuf_thread[i] = ogs_pkbuf_alloc(0, 200); // enough for icmp
		memcpy(recvbuf_thread[i]->data, recvbuf->data, recvbuf->len);
		recvbuf_thread[i]->len = recvbuf->len;
		ogs_pkbuf_free(recvbuf);
		sem_post(&received_sem_ue[i]);
	}

	return NULL;
}

void *thread_s1ap_read(void *arg)
{
    int i;
    int ran_ue_ngap_id = 0;
    int ue_id ;

    while(1) {

        sem_wait(&occupied_s1ap_read);
        if ( all_terminated )
                return NULL;
printf("[thread s1ap enb reading start]\n");
	recvbuf = testgnb_ngap_read(ngap);
printf("[thread s1ap enb reading end]\n");
        //memcpy(recvbuf2->data, recvbuf->data, recvbuf->len);
        //recvbuf2->len = recvbuf->len;
        //printf("[s1ap] RECV: %d\n",recvbuf2->len);
	ran_ue_ngap_id = get_ran_ue_ngap_id(recvbuf);
	ue_id = map_ran_ue[ran_ue_ngap_id];
printf("[ue_id is: %d]\n",ue_id);
        recvbuf_thread[ue_id] = ogs_pkbuf_alloc(NULL, OGS_MAX_SDU_LEN);
        memcpy(recvbuf_thread[ue_id]->data, recvbuf->data, recvbuf->len);
        recvbuf_thread[ue_id]->len = recvbuf->len;
        //ogs_pkbuf_free(recvbuf);
//printf("[thread signal] enb_ue_s1ap_id: %ld\n",enb_ue_s1ap_id);

        sem_post(&received_sem_ue[ue_id]);
    }
    return NULL;
}


abts_suite *global_suite;
void* test_runner(void* arg) {
	int i = *(int*)arg;
    	//signal(SIGINT, hsignal);
	//printf("test_runner: %d\n",i);
	abts_run_test(global_suite, test_icmp_func, &i);
	return NULL;
}
abts_suite *test_ue_context(abts_suite *suite)
{

    suite = ADD_SUITE(suite)
    global_suite = suite;

    int i, ue_id = 0;
    int a[THREADNUM];
    pthread_t enb_reader, gtpu_reader, ue[THREADNUM];

    //sock_init("127.0.0.5", "127.0.0.2");
    sock_init("172.16.158.129", "172.16.158.128"); // ip_5gcore, ip_emulator
    //printf("sock init done!\n");

    pthread_create(&enb_reader, NULL, thread_s1ap_read, NULL);
    pthread_create(&gtpu_reader, NULL, thread_gtpu_read, NULL);
    for ( i = 0 ; i < THREADNUM ; ++i ) { 
	    a[i] = i;
	    icmp_record[2*i] = malloc(sizeof(struct icmp));
	    icmp_record[2*i+1] = malloc(sizeof(struct icmp));
    }
    for ( i = 0 ; i < THREADNUM ; ++i ) {
	    //printf("[i] %d\n",i);
	    pthread_create(&ue[i], NULL, test_runner, (void*)&a[i]);
	    if ( !CONCURRENT ) pthread_join(ue[i], NULL);
    }
     for ( i = 0 ; i < THREADNUM ; ++i )
	    pthread_join(ue[i], NULL);
    all_terminated = 1;
    sem_post(&occupied_s1ap_read);
    sem_post(&occupied_gtpu_read);
    pthread_join(enb_reader, NULL);
    pthread_join(gtpu_reader, NULL);
    sock_close();

        FILE *output_log = fopen("output.log", "a+");

    for ( i = 0 ; i < THREADNUM ; ++i ) {
	    fprintf(output_log, "ue_id: %d\n",i);
	    fprintf(output_log, "init ue msg: %ld\n",ue_log[i].init_ue_msg_time );
	    fprintf(output_log, "auth request: %ld\n",ue_log[i].auth_request_time);
	    fprintf(output_log, "auth response: %ld\n",ue_log[i].auth_response_time);
	    fprintf(output_log, "security mode command: %ld\n",ue_log[i].security_mode_command_time );
	    fprintf(output_log, "security mode complete: %ld\n",ue_log[i].security_mode_complete_time );
	    fprintf(output_log, "ESM info request: %ld\n",ue_log[i].ESM_info_request_time );
	    fprintf(output_log, "ESM info response: %ld\n",ue_log[i].ESM_info_response_time );
	    fprintf(output_log, "UE info: %ld\n",ue_log[i].UE_info_time);
	    fprintf(output_log, "initial_context send: %ld\n",ue_log[i].initial_context_setup_send_time );
	    fprintf(output_log, "initial_context receive: %ld\n",ue_log[i].initial_context_setup_receive_time );
	    fprintf(output_log, "activate EPS: %ld\n",ue_log[i].activate_EPS_time );
	    fprintf(output_log, "EMM receive: %ld\n",ue_log[i].receive_EMM_time);

	    fprintf(output_log, "detach request: %ld\n",ue_log[i].detach_request_time);
	    fprintf(output_log, "UE release command: %ld\n",ue_log[i].UE_release_command_time );
	    fprintf(output_log, "UE release complete: %ld\n",ue_log[i].UE_release_complete_time );
	    fprintf(output_log, "\n");
    }
    fclose( output_log);

   //abts_run_test(suite, test1_func, NULL);
   //abts_run_test(suite, test2_func, NULL);

    return suite;
}
