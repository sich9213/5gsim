/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-PDU-Descriptions"
 * 	found in "../support/ngap-r16.1.0/38413-g10.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps`
 */

#ifndef	_NGAP_SuccessfulOutcome_H_
#define	_NGAP_SuccessfulOutcome_H_


#include <asn_application.h>

/* Including external dependencies */
#include "NGAP_ProcedureCode.h"
#include "NGAP_Criticality.h"
#include <ANY.h>
#include <asn_ioc.h>
#include "NGAP_AMFConfigurationUpdate.h"
#include "NGAP_AMFConfigurationUpdateAcknowledge.h"
#include "NGAP_AMFConfigurationUpdateFailure.h"
#include "NGAP_HandoverCancel.h"
#include "NGAP_HandoverCancelAcknowledge.h"
#include "NGAP_HandoverRequired.h"
#include "NGAP_HandoverCommand.h"
#include "NGAP_HandoverPreparationFailure.h"
#include "NGAP_HandoverRequest.h"
#include "NGAP_HandoverRequestAcknowledge.h"
#include "NGAP_HandoverFailure.h"
#include "NGAP_InitialContextSetupRequest.h"
#include "NGAP_InitialContextSetupResponse.h"
#include "NGAP_InitialContextSetupFailure.h"
#include "NGAP_NGReset.h"
#include "NGAP_NGResetAcknowledge.h"
#include "NGAP_NGSetupRequest.h"
#include "NGAP_NGSetupResponse.h"
#include "NGAP_NGSetupFailure.h"
#include "NGAP_PathSwitchRequest.h"
#include "NGAP_PathSwitchRequestAcknowledge.h"
#include "NGAP_PathSwitchRequestFailure.h"
#include "NGAP_PDUSessionResourceModifyRequest.h"
#include "NGAP_PDUSessionResourceModifyResponse.h"
#include "NGAP_PDUSessionResourceModifyIndication.h"
#include "NGAP_PDUSessionResourceModifyConfirm.h"
#include "NGAP_PDUSessionResourceReleaseCommand.h"
#include "NGAP_PDUSessionResourceReleaseResponse.h"
#include "NGAP_PDUSessionResourceSetupRequest.h"
#include "NGAP_PDUSessionResourceSetupResponse.h"
#include "NGAP_PWSCancelRequest.h"
#include "NGAP_PWSCancelResponse.h"
#include "NGAP_RANConfigurationUpdate.h"
#include "NGAP_RANConfigurationUpdateAcknowledge.h"
#include "NGAP_RANConfigurationUpdateFailure.h"
#include "NGAP_UEContextModificationRequest.h"
#include "NGAP_UEContextModificationResponse.h"
#include "NGAP_UEContextModificationFailure.h"
#include "NGAP_UEContextReleaseCommand.h"
#include "NGAP_UEContextReleaseComplete.h"
#include "NGAP_UERadioCapabilityCheckRequest.h"
#include "NGAP_UERadioCapabilityCheckResponse.h"
#include "NGAP_WriteReplaceWarningRequest.h"
#include "NGAP_WriteReplaceWarningResponse.h"
#include "NGAP_AMFStatusIndication.h"
#include "NGAP_CellTrafficTrace.h"
#include "NGAP_DeactivateTrace.h"
#include "NGAP_DownlinkNASTransport.h"
#include "NGAP_DownlinkNonUEAssociatedNRPPaTransport.h"
#include "NGAP_DownlinkRANConfigurationTransfer.h"
#include "NGAP_DownlinkRANStatusTransfer.h"
#include "NGAP_DownlinkUEAssociatedNRPPaTransport.h"
#include "NGAP_ErrorIndication.h"
#include "NGAP_HandoverNotify.h"
#include "NGAP_InitialUEMessage.h"
#include "NGAP_LocationReport.h"
#include "NGAP_LocationReportingControl.h"
#include "NGAP_LocationReportingFailureIndication.h"
#include "NGAP_NASNonDeliveryIndication.h"
#include "NGAP_OverloadStart.h"
#include "NGAP_OverloadStop.h"
#include "NGAP_Paging.h"
#include "NGAP_PDUSessionResourceNotify.h"
#include "NGAP_PrivateMessage.h"
#include "NGAP_PWSFailureIndication.h"
#include "NGAP_PWSRestartIndication.h"
#include "NGAP_RerouteNASRequest.h"
#include "NGAP_RRCInactiveTransitionReport.h"
#include "NGAP_SecondaryRATDataUsageReport.h"
#include "NGAP_TraceFailureIndication.h"
#include "NGAP_TraceStart.h"
#include "NGAP_UEContextReleaseRequest.h"
#include "NGAP_UERadioCapabilityInfoIndication.h"
#include "NGAP_UETNLABindingReleaseRequest.h"
#include "NGAP_UplinkNASTransport.h"
#include "NGAP_UplinkNonUEAssociatedNRPPaTransport.h"
#include "NGAP_UplinkRANConfigurationTransfer.h"
#include "NGAP_UplinkRANStatusTransfer.h"
#include "NGAP_UplinkUEAssociatedNRPPaTransport.h"
#include "NGAP_UplinkRIMInformationTransfer.h"
#include "NGAP_DownlinkRIMInformationTransfer.h"
#include <OPEN_TYPE.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum NGAP_SuccessfulOutcome__value_PR {
	NGAP_SuccessfulOutcome__value_PR_NOTHING,	/* No components present */
	NGAP_SuccessfulOutcome__value_PR_AMFConfigurationUpdateAcknowledge,
	NGAP_SuccessfulOutcome__value_PR_HandoverCancelAcknowledge,
	NGAP_SuccessfulOutcome__value_PR_HandoverCommand,
	NGAP_SuccessfulOutcome__value_PR_HandoverRequestAcknowledge,
	NGAP_SuccessfulOutcome__value_PR_InitialContextSetupResponse,
	NGAP_SuccessfulOutcome__value_PR_NGResetAcknowledge,
	NGAP_SuccessfulOutcome__value_PR_NGSetupResponse,
	NGAP_SuccessfulOutcome__value_PR_PathSwitchRequestAcknowledge,
	NGAP_SuccessfulOutcome__value_PR_PDUSessionResourceModifyResponse,
	NGAP_SuccessfulOutcome__value_PR_PDUSessionResourceModifyConfirm,
	NGAP_SuccessfulOutcome__value_PR_PDUSessionResourceReleaseResponse,
	NGAP_SuccessfulOutcome__value_PR_PDUSessionResourceSetupResponse,
	NGAP_SuccessfulOutcome__value_PR_PWSCancelResponse,
	NGAP_SuccessfulOutcome__value_PR_RANConfigurationUpdateAcknowledge,
	NGAP_SuccessfulOutcome__value_PR_UEContextModificationResponse,
	NGAP_SuccessfulOutcome__value_PR_UEContextReleaseComplete,
	NGAP_SuccessfulOutcome__value_PR_UERadioCapabilityCheckResponse,
	NGAP_SuccessfulOutcome__value_PR_WriteReplaceWarningResponse
} NGAP_SuccessfulOutcome__value_PR;

/* NGAP_SuccessfulOutcome */
typedef struct NGAP_SuccessfulOutcome {
	NGAP_ProcedureCode_t	 procedureCode;
	NGAP_Criticality_t	 criticality;
	struct NGAP_SuccessfulOutcome__value {
		NGAP_SuccessfulOutcome__value_PR present;
		union NGAP_SuccessfulOutcome__NGAP_value_u {
			NGAP_AMFConfigurationUpdateAcknowledge_t	 AMFConfigurationUpdateAcknowledge;
			NGAP_HandoverCancelAcknowledge_t	 HandoverCancelAcknowledge;
			NGAP_HandoverCommand_t	 HandoverCommand;
			NGAP_HandoverRequestAcknowledge_t	 HandoverRequestAcknowledge;
			NGAP_InitialContextSetupResponse_t	 InitialContextSetupResponse;
			NGAP_NGResetAcknowledge_t	 NGResetAcknowledge;
			NGAP_NGSetupResponse_t	 NGSetupResponse;
			NGAP_PathSwitchRequestAcknowledge_t	 PathSwitchRequestAcknowledge;
			NGAP_PDUSessionResourceModifyResponse_t	 PDUSessionResourceModifyResponse;
			NGAP_PDUSessionResourceModifyConfirm_t	 PDUSessionResourceModifyConfirm;
			NGAP_PDUSessionResourceReleaseResponse_t	 PDUSessionResourceReleaseResponse;
			NGAP_PDUSessionResourceSetupResponse_t	 PDUSessionResourceSetupResponse;
			NGAP_PWSCancelResponse_t	 PWSCancelResponse;
			NGAP_RANConfigurationUpdateAcknowledge_t	 RANConfigurationUpdateAcknowledge;
			NGAP_UEContextModificationResponse_t	 UEContextModificationResponse;
			NGAP_UEContextReleaseComplete_t	 UEContextReleaseComplete;
			NGAP_UERadioCapabilityCheckResponse_t	 UERadioCapabilityCheckResponse;
			NGAP_WriteReplaceWarningResponse_t	 WriteReplaceWarningResponse;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} value;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_SuccessfulOutcome_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_SuccessfulOutcome;
extern asn_SEQUENCE_specifics_t asn_SPC_NGAP_SuccessfulOutcome_specs_1;
extern asn_TYPE_member_t asn_MBR_NGAP_SuccessfulOutcome_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_SuccessfulOutcome_H_ */
#include <asn_internal.h>
