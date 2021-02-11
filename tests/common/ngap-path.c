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
int testngap_get_ran_ue_ngap_id(test_ue_t *test_ue, ogs_pkbuf_t *pkbuf) {
	// not must to get ran_ue_ngap_id
	// possible return the pdu session id, see CASE 4
    int rv;
    int i;  
    int res;
    ogs_ngap_message_t message;

    NGAP_NGAP_PDU_t *pdu = NULL;
    NGAP_InitiatingMessage_t *initiatingMessage = NULL;
    NGAP_SuccessfulOutcome_t *successfulOutcome = NULL;
    NGAP_UnsuccessfulOutcome_t *unsuccessfulOutcome = NULL;

    ogs_assert(test_ue);
    ogs_assert(pkbuf);

    rv = ogs_ngap_decode(&message, pkbuf);
    ogs_assert(rv == OGS_OK);

    pdu = &message;
    ogs_assert(pdu);
//printf("[GET RAN UE ID BEGIN]\n");
    switch (pdu->present) {
    case NGAP_NGAP_PDU_PR_initiatingMessage:
	    //printf("{BRANCH} init msg\n");
        initiatingMessage = pdu->choice.initiatingMessage;
        ogs_assert(initiatingMessage);

        switch (initiatingMessage->procedureCode) {
        case NGAP_ProcedureCode_id_DownlinkNASTransport:
		//printf("[CASE 1]\n");
            testngap_get_ran_ue_ngap_id_downlink_nas_transport(test_ue, pdu);
	    res = test_ue->ran_ue_ngap_id;
            break;
        case NGAP_ProcedureCode_id_InitialContextSetup:
		//printf("[CASE 2]\n");
            testngap_get_ran_ue_ngap_id_initial_context_setup_request(test_ue, pdu);
	    res = test_ue->ran_ue_ngap_id;
            break;
        case NGAP_ProcedureCode_id_UEContextRelease:
		//printf("[CASE 3]\n");
            testngap_get_ran_ue_ngap_id_ue_release_context_command(test_ue, pdu);
	    res = test_ue->ran_ue_ngap_id;
            break;
        case NGAP_ProcedureCode_id_PDUSessionResourceSetup:
		printf("[CASE 4] special handle\n");
		// return the psi
		res = testngap_get_psi_pdu_session_resource_setup_request(test_ue, pdu);
            break;
        case NGAP_ProcedureCode_id_PDUSessionResourceRelease:
		printf("[CASE 5] not handle\n");
            testngap_handle_pdu_session_resource_release_command(test_ue, pdu);
            break;
        case NGAP_ProcedureCode_id_ErrorIndication:
            /* Nothing */
            break;
        default:
            ogs_error("Not implemented(choice:%d, proc:%d)",
                    pdu->present, (int)initiatingMessage->procedureCode);
            break;
        }
        break;
    case NGAP_NGAP_PDU_PR_successfulOutcome :
	    printf("{BRANCH} succ outcome not handle\n");
        successfulOutcome = pdu->choice.successfulOutcome;
        ogs_assert(successfulOutcome);

        switch (successfulOutcome->procedureCode) {
        case NGAP_ProcedureCode_id_NGSetup:
		printf("[CASE 6] not handle\n");
            testngap_handle_ng_setup_response(test_ue, pdu);
            break;
        default:
            ogs_error("Not implemented(choice:%d, proc:%d)",
                    pdu->present, (int)successfulOutcome->procedureCode);
            break;
        }
        break;
    case NGAP_NGAP_PDU_PR_unsuccessfulOutcome :
	    //printf("{BRANCH} unsucc outcome\n");
        unsuccessfulOutcome = pdu->choice.unsuccessfulOutcome;
        ogs_assert(unsuccessfulOutcome);

        switch (unsuccessfulOutcome->procedureCode) {
        case NGAP_ProcedureCode_id_NGSetup:
            break;
        default:
            ogs_error("Not implemented(choice:%d, proc:%d)",
                    pdu->present, (int)unsuccessfulOutcome->procedureCode);
            break;
        }
        break;
    default:
        ogs_error("Not implemented(choice:%d)", pdu->present);
        break;
    }

    ogs_ngap_free(&message);
    ogs_pkbuf_free(pkbuf);
//printf("[GET RAN UE ID END]\n");
return res;
}
void testngap_recv(test_ue_t *test_ue, ogs_pkbuf_t *pkbuf)
{
    int rv;
    int i;  
    ogs_ngap_message_t message;

    NGAP_NGAP_PDU_t *pdu = NULL;
    NGAP_InitiatingMessage_t *initiatingMessage = NULL;
    NGAP_SuccessfulOutcome_t *successfulOutcome = NULL;
    NGAP_UnsuccessfulOutcome_t *unsuccessfulOutcome = NULL;

    ogs_assert(test_ue);
    ogs_assert(pkbuf);

    rv = ogs_ngap_decode(&message, pkbuf);
    //printf("[after decode]\n");
    ogs_assert(rv == OGS_OK);

    pdu = &message;
    ogs_assert(pdu);
printf("[RECV TEST BEGIN]\n");
/*
        printf("SEQ:\n");
        for ( i = 0 ; i < pkbuf->len ; ++i )
                printf("%x ",pkbuf->data[i]);
        printf("\n");
*/
    switch (pdu->present) {
    case NGAP_NGAP_PDU_PR_initiatingMessage:
	    //printf("{BRANCH} init msg\n");
        initiatingMessage = pdu->choice.initiatingMessage;
        ogs_assert(initiatingMessage);

        switch (initiatingMessage->procedureCode) {
        case NGAP_ProcedureCode_id_DownlinkNASTransport:
		//printf("[CASE 1]\n");
            testngap_handle_downlink_nas_transport(test_ue, pdu);
            break;
        case NGAP_ProcedureCode_id_InitialContextSetup:
		//printf("[CASE 2]\n");
            testngap_handle_initial_context_setup_request(test_ue, pdu);
            break;
        case NGAP_ProcedureCode_id_UEContextRelease:
		//printf("[CASE 3]\n");
            testngap_handle_ue_release_context_command(test_ue, pdu);
            break;
        case NGAP_ProcedureCode_id_PDUSessionResourceSetup:
		//printf("[CASE 4]\n");
            testngap_handle_pdu_session_resource_setup_request(test_ue, pdu);
            break;
        case NGAP_ProcedureCode_id_PDUSessionResourceRelease:
		//printf("[CASE 5]\n");
            testngap_handle_pdu_session_resource_release_command(test_ue, pdu);
            break;
        case NGAP_ProcedureCode_id_ErrorIndication:
            /* Nothing */
            break;
        default:
            ogs_error("Not implemented(choice:%d, proc:%d)",
                    pdu->present, (int)initiatingMessage->procedureCode);
            break;
        }
        break;
    case NGAP_NGAP_PDU_PR_successfulOutcome :
//	    printf("{BRANCH} succ outcome\n");
        successfulOutcome = pdu->choice.successfulOutcome;
        ogs_assert(successfulOutcome);

        switch (successfulOutcome->procedureCode) {
        case NGAP_ProcedureCode_id_NGSetup:
            testngap_handle_ng_setup_response(test_ue, pdu);
            break;
        default:
            ogs_error("Not implemented(choice:%d, proc:%d)",
                    pdu->present, (int)successfulOutcome->procedureCode);
            break;
        }
        break;
    case NGAP_NGAP_PDU_PR_unsuccessfulOutcome :
//	    printf("{BRANCH} unsucc outcome\n");
        unsuccessfulOutcome = pdu->choice.unsuccessfulOutcome;
        ogs_assert(unsuccessfulOutcome);

        switch (unsuccessfulOutcome->procedureCode) {
        case NGAP_ProcedureCode_id_NGSetup:
            break;
        default:
            ogs_error("Not implemented(choice:%d, proc:%d)",
                    pdu->present, (int)unsuccessfulOutcome->procedureCode);
            break;
        }
        break;
    default:
        ogs_error("Not implemented(choice:%d)", pdu->present);
        break;
    }

    ogs_ngap_free(&message);
    ogs_pkbuf_free(pkbuf);
printf("[RECV TEST END]\n");
}

void testngap_send_to_nas(test_ue_t *test_ue, NGAP_NAS_PDU_t *nasPdu)
{
    ogs_nas_5gs_security_header_t *sh = NULL;
    ogs_nas_security_header_type_t security_header_type;

    ogs_nas_5gmm_header_t *h = NULL;
    ogs_pkbuf_t *nasbuf = NULL;

    ogs_assert(test_ue);
    ogs_assert(nasPdu);

    /* The Packet Buffer(pkbuf_t) for NAS message MUST make a HEADROOM. 
     * When calculating AES_CMAC, we need to use the headroom of the packet. */
    nasbuf = ogs_pkbuf_alloc(NULL, OGS_NAS_HEADROOM+nasPdu->size);
    ogs_assert(nasbuf);
    ogs_pkbuf_reserve(nasbuf, OGS_NAS_HEADROOM);
    ogs_pkbuf_put_data(nasbuf, nasPdu->buf, nasPdu->size);

    sh = (ogs_nas_5gs_security_header_t *)nasbuf->data;
    ogs_assert(sh);

    memset(&security_header_type, 0, sizeof(ogs_nas_security_header_type_t));
    switch(sh->security_header_type) {
    case OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE:
        break;
    case OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED:
        security_header_type.integrity_protected = 1;
        ogs_pkbuf_pull(nasbuf, 7);
        break;
    case OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED:
        security_header_type.integrity_protected = 1;
        security_header_type.ciphered = 1;
        ogs_pkbuf_pull(nasbuf, 7);
        break;
    case OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT:
        security_header_type.integrity_protected = 1;
        security_header_type.new_security_context = 1;
        ogs_pkbuf_pull(nasbuf, 7);
        break;
    case OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT:
        security_header_type.integrity_protected = 1;
        security_header_type.ciphered = 1;
        security_header_type.new_security_context = 1;
        ogs_pkbuf_pull(nasbuf, 7);
        break;
    default:
        ogs_error("Not implemented(security header type:0x%x)",
                sh->security_header_type);
        ogs_assert_if_reached();
    }

    h = (ogs_nas_5gmm_header_t *)nasbuf->data;
    ogs_assert(h);

    if (h->message_type == OGS_NAS_5GS_SECURITY_MODE_COMMAND) {
        ogs_nas_5gs_message_t message;
        int rv;

        rv = ogs_nas_5gmm_decode(&message, nasbuf);
        ogs_assert(rv == OGS_OK);

        testgmm_handle_security_mode_command(test_ue,
                &message.gmm.security_mode_command);
    }

    if (test_nas_5gs_security_decode(test_ue,
            security_header_type, nasbuf) != OGS_OK) {
        ogs_error("nas_eps_security_decode failed()");
        ogs_assert_if_reached();
    }

    if (h->extended_protocol_discriminator ==
            OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM) {
        testgmm_recv(test_ue, nasbuf);
    } else {
        ogs_error("Unknown NAS Protocol discriminator 0x%02x",
                  h->extended_protocol_discriminator);
        ogs_assert_if_reached();
    }
}

