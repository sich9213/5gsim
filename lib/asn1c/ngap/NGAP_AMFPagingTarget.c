/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "../support/ngap-r16.1.0/38413-g10.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps`
 */

#include "NGAP_AMFPagingTarget.h"

#include "NGAP_GlobalRANNodeID.h"
#include "NGAP_TAI.h"
#include "NGAP_ProtocolIE-SingleContainer.h"
static asn_oer_constraints_t asn_OER_type_NGAP_AMFPagingTarget_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_NGAP_AMFPagingTarget_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  2 }	/* (0..2) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_NGAP_AMFPagingTarget_1[] = {
	{ ATF_POINTER, 0, offsetof(struct NGAP_AMFPagingTarget, choice.globalRANNodeID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_NGAP_GlobalRANNodeID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"globalRANNodeID"
		},
	{ ATF_POINTER, 0, offsetof(struct NGAP_AMFPagingTarget, choice.tAI),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_TAI,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tAI"
		},
	{ ATF_POINTER, 0, offsetof(struct NGAP_AMFPagingTarget, choice.choice_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_ProtocolIE_SingleContainer_6979P0,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"choice-Extensions"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_NGAP_AMFPagingTarget_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* globalRANNodeID */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* tAI */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* choice-Extensions */
};
asn_CHOICE_specifics_t asn_SPC_NGAP_AMFPagingTarget_specs_1 = {
	sizeof(struct NGAP_AMFPagingTarget),
	offsetof(struct NGAP_AMFPagingTarget, _asn_ctx),
	offsetof(struct NGAP_AMFPagingTarget, present),
	sizeof(((struct NGAP_AMFPagingTarget *)0)->present),
	asn_MAP_NGAP_AMFPagingTarget_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_NGAP_AMFPagingTarget = {
	"AMFPagingTarget",
	"AMFPagingTarget",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_NGAP_AMFPagingTarget_constr_1, &asn_PER_type_NGAP_AMFPagingTarget_constr_1, CHOICE_constraint },
	asn_MBR_NGAP_AMFPagingTarget_1,
	3,	/* Elements count */
	&asn_SPC_NGAP_AMFPagingTarget_specs_1	/* Additional specs */
};

