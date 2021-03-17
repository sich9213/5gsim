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
#define THREADNUM 1 
#define CONCURRENT 1 

#define DEBUG 1
#define REGISTRAION 1
#define UPFGTP 2
#define TEST_MODE UPFGTP

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
    clock_t recv_id_req_time;
    clock_t send_id_res_time;
	clock_t auth_request_time;
    clock_t auth_response_time ;
	clock_t security_mode_command_time ;
	clock_t security_mode_complete_time ;
	clock_t ESM_info_request_time ;
	clock_t ESM_info_response_time ;
	clock_t UE_info_time ;
	clock_t recv_initial_context_setup_request_time;
	clock_t send_initial_context_setup_failure_time ;
    clock_t activate_EPS_time ;
    clock_t receive_EMM_time ;
	clock_t EMM_service_request_time;
    clock_t ping_time ;
	clock_t detach_request_time ;
	clock_t recv_UE_context_release_command_time ;
	clock_t send_UE_context_release_complete_time ;
	clock_t last_update ;

    clock_t amf_auth_time ;
    clock_t auth_start_time ;

    // UPF-GTP
    clock_t send_initial_context_setup_response_time ;
    clock_t send_pdu_session_establishment_request_time ;
    clock_t recv_pdu_session_resource_setup_request_time ;
    clock_t send_pdu_session_resource_setup_response_time ;
    clock_t send_gtpu_icmp_packet_time ;
    clock_t recv_gtpu_icmp_packet_time ;

    clock_t gtpu_icmp_rtt ;
    clock_t gtpu_icmp_start_time ;

    clock_t upf_pdu_session_time ;
    clock_t upf_pdu_start_time ;


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
    // log_reset_time(log->last_update);

    /* Send Registration request */
#if DEBUG
    printf("[SEND INIT UE MSG START]: %d\n",ue_id);
#endif
    log_reset_time(log->last_update);

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
    // printf("[SEND INIT UE MSG DONE]: %d\n",ue_id);
    // log_update( log->init_ue_msg_time, log->last_update );
    pthread_mutex_unlock(&s1ap_send_lock);

    log_update( log->init_ue_msg_time, log->last_update );
#if DEBUG
    printf("[SEND INIT UE MSG DONE]: %d\n",ue_id);
#endif

    /* Receive Authentication request */
    /*
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    */
    //printf("[RECV AUTH REQUEST DONE]: %d\n", ue_id);
#if DEBUG
    printf("[RECV AUTH REQUEST START]: %d\n", ue_id);
#endif
    log_reset_time(log->last_update);

    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ue_id]);
    testngap_recv(test_ue, recvbuf_thread[ue_id]);
    ogs_pkbuf_free(recvbuf_thread[ue_id]);
    // printf("[RECV AUTH REQUEST DONE]: %d\n", ue_id);
    // log_update(log->auth_request_time, log->last_update);
    log_update(log->auth_request_time, log->last_update);
#if DEBUG
    printf("[RECV AUTH REQUEST DONE]: %d\n", ue_id);
#endif    

    /* Send Authentication response */
#if DEBUG
    printf("[SEND AUTH RESPONSE START]: %d\n",ue_id);
#endif
    log_reset_time(log->last_update);

    pthread_mutex_lock(&s1ap_send_lock);
    gmmbuf = testgmm_build_authentication_response(test_ue);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);

    log_reset_time(log->auth_start_time);

    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    pthread_mutex_unlock(&s1ap_send_lock);
    
    // printf("[SEND AUTH RESPONSE DONE]: %d\n",ue_id);
    // log_update( log->auth_response_time, log->last_update);
    log_update( log->auth_response_time, log->last_update);
#if DEBUG
    printf("[SEND AUTH RESPONSE DONE]: %d\n",ue_id);
#endif

    /* Receive Security mode command */
    /*
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    */
    //printf("[RECV SECURITY MODE DONE]: %d\n", ue_id);

#if DEBUG
    printf("[RECV SECURITY MODE START]: %d\n", ue_id);
#endif
    log_reset_time(log->last_update);

    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ue_id]);
    testngap_recv(test_ue, recvbuf_thread[ue_id]);

    log_update( log->amf_auth_time, log->auth_start_time);

    ogs_pkbuf_free(recvbuf_thread[ue_id]);

    // printf("[RECV SECURITY MODE DONE]: %d\n", ue_id);
    // log_update( log->security_mode_command_time, log->last_update);
    log_update( log->security_mode_command_time, log->last_update);
#if DEBUG
    printf("[RECV SECURITY MODE DONE]: %d\n", ue_id);
#endif

    /* Send Security mode complete */
#if DEBUG
    printf("[SEND SECURITY MODE START]: %d\n",ue_id);
#endif
    log_reset_time(log->last_update);

    pthread_mutex_lock(&s1ap_send_lock);
    gmmbuf = testgmm_build_security_mode_complete(test_ue, nasbuf);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    pthread_mutex_unlock(&s1ap_send_lock);
    // printf("[SEND SECURITY MODE DONE]: %d\n",ue_id);
    // log_update(log->security_mode_complete_time, log->last_update);
    log_update(log->security_mode_complete_time, log->last_update);
#if DEBUG
    printf("[SEND SECURITY MODE DONE]: %d\n",ue_id);
#endif

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
    // printf("[RECV INITIAL CONTEXT SETUP DONE]: %d\n", ue_id);
#if DEBUG
    printf("[RECV INITIAL CONTEXT SETUP REQUEST START]: %d\n", ue_id);
#endif
    log_reset_time(log->last_update);

    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ue_id]);
    testngap_recv(test_ue, recvbuf_thread[ue_id]);
    ogs_pkbuf_free(recvbuf_thread[ue_id]);
    // printf("[RECV INITIAL CONTEXT SETUP DONE]: %d\n", ue_id);
    // log_update( log->recv_initial_context_setup_request_time, log->last_update);
    log_update( log->recv_initial_context_setup_request_time, log->last_update);
#if DEBUG
    printf("[RECV INITIAL CONTEXT SETUP REQUEST DONE]: %d\n", ue_id);
#endif

    /* Send InitialContextSetupResponse */
#if DEBUG
    printf("[SEND INITIAL CONTEXT SETUP RESPONSE START]: %d\n", ue_id);
#endif
    log_reset_time(log->last_update);

    pthread_mutex_lock(&s1ap_send_lock);
    sendbuf = testngap_build_initial_context_setup_response(test_ue, false);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    pthread_mutex_unlock(&s1ap_send_lock);

    // printf("[SEND INIT CONTEXT SETUP RESPONSE DONE]: %d\n",ue_id);
    log_update( log->send_initial_context_setup_response_time , log->last_update);
#if DEBUG
    printf("[SEND INITIAL CONTEXT SETUP RESPONSE DONE]: %d\n", ue_id);
#endif

    /* GUTI Not Present
     * SKIP Send Registration complete */
    /* SKIP Receive Configuration update command */

    /* Send Registration complete */

    // gmmbuf = testgmm_build_registration_complete(test_ue);
    // ABTS_PTR_NOTNULL(tc, gmmbuf);
    // sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    // ABTS_PTR_NOTNULL(tc, sendbuf);
    // rv = testgnb_ngap_send(ngap, sendbuf);
    // ABTS_INT_EQUAL(tc, OGS_OK, rv);

    // /* Receive Configuration update command */
    // recvbuf = testgnb_ngap_read(ngap);
    // ABTS_PTR_NOTNULL(tc, recvbuf);
    // testngap_recv(test_ue, recvbuf);



    /* Send PDU session establishment request */
#if DEBUG
    printf("[SEND PDU SESSION ESTABLISHMENT REQUEST START]: %d\n", ue_id);
#endif
    log_reset_time(log->last_update);

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

    log_reset_time(log->upf_pdu_start_time);

    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    // printf("[SEND PDU SESION ESTABLISHMENT REQUEST DONE]: %d\n",ue_id);
    pthread_mutex_unlock(&s1ap_send_lock);

    log_update( log->send_pdu_session_establishment_request_time, log->last_update);
#if DEBUG
    printf("[SEND PDU SESSION ESTABLISHMENT REQUEST DONE]: %d\n", ue_id);
#endif

    /* Receive PDUSessionResourceSetupRequest +
     * DL NAS transport +
     * PDU session establishment accept */
    /*recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc,
            NGAP_ProcedureCode_id_PDUSessionResourceSetup,
            test_ue->ngap_procedure_code);*/

    //printf("[RECV PDU SETUP REQUEST DONE]: %d\n", ue_id);
#if DEBUG
    printf("[RECV PDU SESSION RESOURCE SETUP REQUEST START]: %d\n", ue_id);
#endif
    log_reset_time(log->last_update);

    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ue_id]);
    testngap_recv(test_ue, recvbuf_thread[ue_id]);

    log_update( log->upf_pdu_session_time, log->upf_pdu_start_time);

    ogs_pkbuf_free(recvbuf_thread[ue_id]);
    // printf("[RECV PDU SETUP REQUEST DONE]: %d\n",ue_id);
    log_update( log->recv_pdu_session_resource_setup_request_time, log->last_update);
#if DEBUG
    printf("[RECV PDU SESSION RESOURCE SETUP REQUEST DONE]: %d\n", ue_id);
#endif

    /* Send PDUSessionResourceSetupResponse */
#if DEBUG
    printf("[SEND PDU SESSION RESOURCE SETUP RESPONSE START]: %d\n", ue_id);
#endif
    log_reset_time(log->last_update);

    pthread_mutex_lock(&s1ap_send_lock);
    sendbuf = testngap_sess_build_pdu_session_resource_setup_response(sess);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    pthread_mutex_unlock(&s1ap_send_lock);

    // printf("[SEND PDU SETUP RESPONSE DONE]: %d\n",ue_id);
    log_update( log->send_pdu_session_resource_setup_response_time, log->last_update);
#if DEBUG
    printf("[SEND PDU SESSION RESOURCE SETUP RESPONSE DONE]: %d\n", ue_id);
#endif

    /* Send GTP-U ICMP Packet */
#if DEBUG
    printf("[SEND GTPU ICMP PACKET START]: %d\n", ue_id);
#endif
    log_reset_time(log->last_update);

    pthread_mutex_lock(&s1ap_send_lock);
    qos_flow = test_qos_flow_find_by_qfi(sess, 1);
    ogs_assert(qos_flow);
#if DEBUG
    printf("UPF GTP Destination ip is: %s\n",TEST_PING_IPV4);
#endif

    rv = test_gtpu_send_ping_2(gtpu, qos_flow, TEST_PING_IPV4, icmp_record[ue_id]);
    
    log_reset_time(log->gtpu_icmp_start_time);

    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    pthread_mutex_unlock(&s1ap_send_lock);
    // printf("[SEND GTP ICMP DONE]: %d\n",ue_id);
    log_update( log->send_gtpu_icmp_packet_time, log->last_update);
#if DEBUG
    printf("[SEND GTPU ICMP PACKET DONE]: %d\n", ue_id);
#endif

    /* Receive GTP-U ICMP Packet */
    /*
    recvbuf = testgnb_gtpu_read(gtpu);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);*/
#if DEBUG
    printf("[RECV GTPU ICMP PACKET START]: %d\n", ue_id);
#endif
    log_reset_time(log->last_update);

    sem_post(&occupied_gtpu_read);
    sem_wait(&received_sem_ue[ue_id]);
    log_update( log->gtpu_icmp_rtt, log->gtpu_icmp_start_time);

    // printf("[Receive GTP-U ICMP Packet DONE]: %d\n",ue_id);
    log_update( log->recv_gtpu_icmp_packet_time, log->last_update);
#if DEBUG
    printf("[RECV GTPU ICMP PACKET DONE]: %d\n", ue_id);
#endif

    ogs_msleep(300);

    /* Send Initial context setup failure */
#if DEBUG
    printf("[SEND INITIAL CONTEXT SETUP FAILURE START]: %d\n",ue_id);
#endif
    log_reset_time(log->last_update);

    pthread_mutex_lock(&s1ap_send_lock);
    sendbuf = testngap_build_initial_context_setup_failure(test_ue,
            NGAP_Cause_PR_radioNetwork,
            NGAP_CauseRadioNetwork_radio_connection_with_ue_lost);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    pthread_mutex_unlock(&s1ap_send_lock);
    // printf("[SEND INITIAL CONTEXT SETUP FAILURE DONE]: %d\n",ue_id);
    log_update( log->send_initial_context_setup_failure_time, log->last_update);
#if DEBUG
    printf("[SEND INITIAL CONTEXT SETUP FAILURE DONE]: %d\n",ue_id);
#endif
  

    /* Receive UEContextReleaseCommand */
    /*recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc,
            NGAP_ProcedureCode_id_UEContextRelease,
            test_ue->ngap_procedure_code);*/
    // printf("[Receive UEContextReleaseCommand DONE]: %d\n",ue_id);
#if DEBUG
    printf("[RECV UE CONTEXT RELEASE COMMAND START]: %d\n", ue_id);
#endif
    log_reset_time(log->last_update);

    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ue_id]);
    testngap_recv(test_ue, recvbuf_thread[ue_id]);
    ogs_pkbuf_free(recvbuf_thread[ue_id]);
    // printf("[Receive UEContextReleaseCommand DONE]: %d\n",ue_id);
    log_update( log->recv_UE_context_release_command_time, log->last_update);
#if DEBUG
    printf("[RECV UE CONTEXT RELEASE COMMAND DONE]: %d\n", ue_id);
#endif


    /* Send UEContextReleaseComplete */
#if DEBUG
    printf("[RECV UE CONTEXT RELEASE COMPLETE START]: %d\n",ue_id);
#endif
    log_reset_time(log->last_update);

    pthread_mutex_lock(&s1ap_send_lock);
    sendbuf = testngap_build_ue_context_release_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    pthread_mutex_unlock(&s1ap_send_lock);
    // printf("[RECV UE CONTEXT RELEASE COMPLETE DONE]: %d\n",ue_id);
    log_update( log->send_UE_context_release_complete_time, log->last_update);
#if DEBUG
    printf("[SEND UE CONTEXT RELEASE COMPLETE DONE]: %d\n",ue_id);
#endif

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
    

    /* Send Registration request */
#if DEBUG
    printf("[SEND INIT UE MSG START]: %d\n",ue_id);
#endif
    log_reset_time(log->last_update);
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
    //printf("ran_ue_ngap_id: %d\n",test_ue->ran_ue_ngap_id);
    pthread_mutex_unlock(&s1ap_send_lock);

    log_update( log->init_ue_msg_time, log->last_update );
#if DEBUG
    printf("[SEND INIT UE MSG DONE]: %d\n",ue_id);
#endif
    /* Receive DownlinkNASTransport +
     * Registration accept */
    /*
    printf("[RECV DownlinkNASTransport + Registration accept START]: %d\n", ue_id);
    //recvbuf = testgnb_ngap_read(ngap);
    //ABTS_PTR_NOTNULL(tc, recvbuf);
    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ue_id]);
    testngap_recv(test_ue, recvbuf_thread[ue_id]);
    ABTS_INT_EQUAL(tc,
            NGAP_ProcedureCode_id_DownlinkNASTransport,
            test_ue->ngap_procedure_code);

    ogs_pkbuf_free(recvbuf_thread[ue_id]);

    log_update(log->recv_id_req_time, log->last_update);
    printf("[RECV DownlinkNASTransport + Registration accept DONE]: %d\n", ue_id);
*/



    /* Receive Identity request */
#if DEBUG
    printf("[RECV INDENTITY REQUEST START]: %d\n", ue_id);
#endif
    log_reset_time(log->last_update);

    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ue_id]);
    testngap_recv(test_ue, recvbuf_thread[ue_id]);
    ogs_pkbuf_free(recvbuf_thread[ue_id]);

    log_update(log->recv_id_req_time, log->last_update);
#if DEBUG
    printf("[RECV INDENTITY REQUEST DONE]: %d\n", ue_id);
#endif

    /* Send Identity response */
#if DEBUG
    printf("[SEND INDENTITY RESPONSE START]: %d\n", ue_id);
#endif
    gmmbuf = testgmm_build_identity_response(test_ue);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    log_update(log->send_id_res_time, log->last_update);
#if DEBUG
    printf("[SEND INDENTITY RESPONSE DONE]: %d\n", ue_id);
#endif

    /* Receive Authentication request */
    /* 
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);  
   */
#if DEBUG
    printf("[RECV AUTH REQUEST START]: %d\n", ue_id);
#endif
    log_reset_time(log->last_update);

    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ue_id]);
    testngap_recv(test_ue, recvbuf_thread[ue_id]);
    ogs_pkbuf_free(recvbuf_thread[ue_id]);

    log_update(log->auth_request_time, log->last_update);
#if DEBUG
    printf("[RECV AUTH REQUEST DONE]: %d\n", ue_id);
#endif    

    /* Send Authentication response */
#if DEBUG
    printf("[SEND AUTH RESPONSE START]: %d\n",ue_id);
#endif
    log_reset_time(log->last_update);

    pthread_mutex_lock(&s1ap_send_lock);
    gmmbuf = testgmm_build_authentication_response(test_ue);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    
    log_reset_time(log->auth_start_time);
    
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    pthread_mutex_unlock(&s1ap_send_lock);

    log_update( log->auth_response_time, log->last_update);
#if DEBUG
    printf("[SEND AUTH RESPONSE DONE]: %d\n",ue_id);
#endif
    /* Receive Security mode command */
/*
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    */
#if DEBUG
    printf("[RECV SECURITY MODE START]: %d\n", ue_id);
#endif
    log_reset_time(log->last_update);

    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ue_id]);
    testngap_recv(test_ue, recvbuf_thread[ue_id]);
    
    log_update( log->amf_auth_time, log->auth_start_time);

    ogs_pkbuf_free(recvbuf_thread[ue_id]);

    log_update( log->security_mode_command_time, log->last_update);
#if DEBUG
    printf("[RECV SECURITY MODE DONE]: %d\n", ue_id);
#endif

    /* Send Security mode complete */
#if DEBUG
    printf("[SEND SECURITY MODE START]: %d\n",ue_id);
#endif
    log_reset_time(log->last_update);

    pthread_mutex_lock(&s1ap_send_lock);
    gmmbuf = testgmm_build_security_mode_complete(test_ue, nasbuf);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    pthread_mutex_unlock(&s1ap_send_lock);

    log_update(log->security_mode_complete_time, log->last_update);
#if DEBUG
    printf("[SEND SECURITY MODE DONE]: %d\n",ue_id);
#endif    

    /* Receive Initial context setup request + Registration accept */
/*
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    */
#if DEBUG
    printf("[RECV INITIAL CONTEXT SETUP REQUEST START]: %d\n", ue_id);
#endif
    log_reset_time(log->last_update);

    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ue_id]);
    testngap_recv(test_ue, recvbuf_thread[ue_id]);
    /* ABTS_INT_EQUAL(tc,
            NGAP_ProcedureCode_id_InitialContextSetup,
            test_ue->ngap_procedure_code);
            */
    ogs_pkbuf_free(recvbuf_thread[ue_id]);
    
    log_update( log->recv_initial_context_setup_request_time, log->last_update);
#if DEBUG
    printf("[RECV INITIAL CONTEXT SETUP REQUEST DONE]: %d\n", ue_id);
#endif
    

    /* Send Initial context setup failure */
/*
    pthread_mutex_lock(&s1ap_send_lock);
    sendbuf = testngap_build_initial_context_setup_failure(test_ue,
            NGAP_Cause_PR_radioNetwork,
            NGAP_CauseRadioNetwork_radio_connection_with_ue_lost);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    pthread_mutex_unlock(&s1ap_send_lock);

    log_update( log->send_initial_context_setup_failure_time, log->last_update);
    printf("[SEND INITIAL CONTEXT SETUP FAILURE DONE]: %d\n",ue_id);
*/

    /* Send Initial context setup failure */
#if DEBUG
    printf("[SEND INITIAL CONTEXT SETUP FAILURE START]: %d\n",ue_id);
#endif

    log_reset_time(log->last_update);

    pthread_mutex_lock(&s1ap_send_lock);
    sendbuf = testngap_build_initial_context_setup_failure(test_ue,
            NGAP_Cause_PR_radioNetwork,
            NGAP_CauseRadioNetwork_radio_connection_with_ue_lost);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    pthread_mutex_unlock(&s1ap_send_lock);

    log_update( log->send_initial_context_setup_failure_time, log->last_update);
#if DEBUG
    printf("[SEND INITIAL CONTEXT SETUP FAILURE DONE]: %d\n",ue_id);
#endif
  


    /* Receive UE context release command */
/*
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    */
#if DEBUG
    printf("[RECV UE CONTEXT RELEASE COMMAND START]: %d\n", ue_id);
#endif
    log_reset_time(log->last_update);

    sem_post(&occupied_s1ap_read);
    sem_wait(&received_sem_ue[ue_id]);
    testngap_recv(test_ue, recvbuf_thread[ue_id]);
    ogs_pkbuf_free(recvbuf_thread[ue_id]);

    log_update( log->recv_UE_context_release_command_time, log->last_update);
#if DEBUG
    printf("[RECV UE CONTEXT RELEASE COMMAND DONE]: %d\n", ue_id);
#endif


    /* Send UE context release complete */

#if DEBUG
    printf("[RECV UE CONTEXT RELEASE COMPLETE START]: %d\n",ue_id);
#endif
    log_reset_time(log->last_update);

    pthread_mutex_lock(&s1ap_send_lock);
    sendbuf = testngap_build_ue_context_release_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    pthread_mutex_unlock(&s1ap_send_lock);

    log_update( log->send_UE_context_release_complete_time, log->last_update);
#if DEBUG
    printf("[RECV UE CONTEXT RELEASE COMPLETE DONE]: %d\n",ue_id);
#endif

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
#if DEBUG
printf("[thread s1ap enb reading start]\n");
#endif

	recvbuf = testgnb_ngap_read(ngap);
#if DEBUG
printf("[thread s1ap enb reading end]\n");
#endif

        //memcpy(recvbuf2->data, recvbuf->data, recvbuf->len);
        //recvbuf2->len = recvbuf->len;
        //printf("[s1ap] RECV: %d\n",recvbuf2->len);
	ran_ue_ngap_id = get_ran_ue_ngap_id(recvbuf);
	ue_id = map_ran_ue[ran_ue_ngap_id];
#if DEBUG
printf("[ue_id is: %d]\n",ue_id);
#endif

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

#if TEST_MODE == REGISTRAION
    // Registration
	abts_run_test(global_suite, test_registration_func, &i);
#elif TEST_MODE == UPFGTP
	// UPF
	abts_run_test(global_suite, test_icmp_func, &i);
#endif

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
    // sock_init("172.16.158.129", "172.16.158.128"); // ip_5gcore, ip_emulator
    //sock_init("192.168.180.134", "192.168.180.133"); // ip_5gcore, ip_emulator
    // OGS
    sock_init("10.10.1.1", "10.10.1.4"); // ip_5gcore, ip_emulator
    //printf("sock init done!\n");

    // FILE *output_log = fopen("output.log", "a+");
    FILE *output_log = fopen("output.log", "a+");
    fprintf(output_log, "REGISTRATION PERFORMANCE MEASUREMENT START\n");
    fprintf(output_log, "###%dUE(s)\n", THREADNUM);
    printf("REGISTRATION PERFORMANCE MEASUREMENT START\n");
    printf("###%dUE(s)\n", THREADNUM);

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


    for ( i = 0 ; i < THREADNUM ; ++i ) {
	    fprintf(output_log, "ue_id: %d\n",i);
	    fprintf(output_log, "###SEND REGISTRATION REQUEST###%d###%.3f\n",ue_id, (double)ue_log[i].init_ue_msg_time/1000 );
      
      fprintf(output_log, "###RECV Identification REQUEST###%d###%.3f\n",ue_id, (double)ue_log[i].recv_id_req_time/1000);
	    fprintf(output_log, "###SEND Identification RESPONSE###%d###%.3f\n",ue_id, (double)ue_log[i].send_id_res_time)/1000;
	    
      fprintf(output_log, "###RECV AUTH REQUEST###%d###%.3f\n",ue_id, (double)ue_log[i].auth_request_time/1000);
	    fprintf(output_log, "###SEND AUTH RESPONSE###%d###%.3f\n",ue_id, (double)ue_log[i].auth_response_time)/1000;
      
      fprintf(output_log, "###AMF AUTH TIME###%d###%.3f\n",ue_id, (double)ue_log[i].amf_auth_time/1000 );
	    fprintf(output_log, "###RECV SECURITY MODE COMMAND###%d###%.3f\n",ue_id, (double)ue_log[i].security_mode_command_time/1000 );
	    fprintf(output_log, "###SEND SECURITY MODE COMPLETE###%d###%.3f\n",ue_id, (double)ue_log[i].security_mode_complete_time/1000 );

      fprintf(output_log, "###RECV INITIAL CONTEXT SETUP REQUEST###%d###%.3f\n",ue_id, (double)ue_log[i].recv_initial_context_setup_request_time/1000 );
      fprintf(output_log, "###SEND INITIAL CONTEXT SETUP FAILURE###%d###%.3f\n",ue_id, (double)ue_log[i].send_initial_context_setup_failure_time/1000 );
	    fprintf(output_log, "###RECV UE CONTEXT RELEASE COMMAND###%d###%.3f\n",ue_id, (double)ue_log[i].recv_UE_context_release_command_time/1000 );
	    fprintf(output_log, "###SEND UE CONTEXT RELEASE COMPLETE###%d###%.3f\n",ue_id, (double)ue_log[i].send_UE_context_release_complete_time/1000 );

	    fprintf(output_log, "\n");
    }
    fprintf(output_log, "REGISTRATION PERFORMANCE MEASUREMENT END\n");
    fprintf(output_log, "###%dUE(s)\n", THREADNUM);
    printf("REGISTRATION PERFORMANCE MEASUREMENT END\n");
    printf("###%dUE(s)\n", THREADNUM);
    fclose( output_log);

    for ( i = 0 ; i < THREADNUM ; ++i ) {
	    printf("ue_id: %d\n",i);
	    printf("###SEND REGISTRATION REQUEST###%d###%.3f\n",ue_id, (double)ue_log[i].init_ue_msg_time/1000 );

      printf("###RECV Identification REQUEST###%d###%.3f\n",ue_id, (double)ue_log[i].recv_id_req_time/1000);
	    printf("###SEND Identification RESPONSE###%d###%.3f\n",ue_id, (double)ue_log[i].send_id_res_time)/1000;
	    
	    printf("###RECV AUTH REQUEST###%d###%.3f\n",ue_id, (double)ue_log[i].auth_request_time/1000);
	    printf("###SEND AUTH RESPONSE###%d###%.3f\n",ue_id, (double)ue_log[i].auth_response_time)/1000;
      printf("###AMF AUTH TIME###%d###%.3f\n",ue_id, (double)ue_log[i].amf_auth_time/1000 );
	    printf("###RECV SECURITY MODE COMMAND###%d###%.3f\n",ue_id, (double)ue_log[i].security_mode_command_time/1000 );
	    printf("###SEND SECURITY MODE COMPLETE###%d###%.3f\n",ue_id, (double)ue_log[i].security_mode_complete_time/1000 );
	    // printf("ESM info request: %.3f\n",(double)ue_log[i].ESM_info_request_time/1000 );
      // printf("ESM info response: %.3f\n",(double)ue_log[i].ESM_info_response_time/1000 );
	    // printf("UE info: %.3f\n",(double)ue_log[i].UE_info_time/1000);
	    printf("###RECV INITIAL CONTEXT SETUP REQUEST###%d###%.3f\n",ue_id, (double)ue_log[i].recv_initial_context_setup_request_time/1000 );

      printf("###SEND INITIAL CONTEXT SETUP FAILURE###%d###%.3f\n",ue_id, (double)ue_log[i].send_initial_context_setup_failure_time/1000 );
	    
	    // printf("activate EPS: %.3f\n",(double)ue_log[i].activate_EPS_time/1000 );
	    // printf("EMM receive: %.3f\n",(double)ue_log[i].receive_EMM_time/1000);

	    // printf("detach request: %.3f\n",(double)ue_log[i].detach_request_time/1000);
	    printf("###RECV UE CONTEXT RELEASE COMMAND###%d###%.3f\n",ue_id, (double)ue_log[i].recv_UE_context_release_command_time/1000 );
	    printf("###SEND UE CONTEXT RELEASE COMPLETE###%d###%.3f\n",ue_id, (double)ue_log[i].send_UE_context_release_complete_time/1000 );


	    printf("\n");
    }

   //abts_run_test(suite, test1_func, NULL);
   //abts_run_test(suite, test2_func, NULL);

    return suite;
}

