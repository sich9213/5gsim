/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "../support/ngap-r16.1.0/38413-g10.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps`
 */

#include "NGAP_LastVisitedCellInformation.h"

#include "NGAP_LastVisitedNGRANCellInformation.h"
#include "NGAP_ProtocolIE-SingleContainer.h"
static asn_oer_constraints_t asn_OER_type_NGAP_LastVisitedCellInformation_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
asn_per_constraints_t asn_PER_type_NGAP_LastVisitedCellInformation_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  0,  4 }	/* (0..4) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_NGAP_LastVisitedCellInformation_1[] = {
	{ ATF_POINTER, 0, offsetof(struct NGAP_LastVisitedCellInformation, choice.nGRANCell),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_LastVisitedNGRANCellInformation,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"nGRANCell"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct NGAP_LastVisitedCellInformation, choice.eUTRANCell),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_LastVisitedEUTRANCellInformation,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"eUTRANCell"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct NGAP_LastVisitedCellInformation, choice.uTRANCell),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_LastVisitedUTRANCellInformation,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"uTRANCell"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct NGAP_LastVisitedCellInformation, choice.gERANCell),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_LastVisitedGERANCellInformation,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"gERANCell"
		},
	{ ATF_POINTER, 0, offsetof(struct NGAP_LastVisitedCellInformation, choice.choice_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_ProtocolIE_SingleContainer_6979P10,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"choice-Extensions"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_NGAP_LastVisitedCellInformation_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* nGRANCell */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* eUTRANCell */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* uTRANCell */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* gERANCell */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* choice-Extensions */
};
asn_CHOICE_specifics_t asn_SPC_NGAP_LastVisitedCellInformation_specs_1 = {
	sizeof(struct NGAP_LastVisitedCellInformation),
	offsetof(struct NGAP_LastVisitedCellInformation, _asn_ctx),
	offsetof(struct NGAP_LastVisitedCellInformation, present),
	sizeof(((struct NGAP_LastVisitedCellInformation *)0)->present),
	asn_MAP_NGAP_LastVisitedCellInformation_tag2el_1,
	5,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_NGAP_LastVisitedCellInformation = {
	"LastVisitedCellInformation",
	"LastVisitedCellInformation",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ &asn_OER_type_NGAP_LastVisitedCellInformation_constr_1, &asn_PER_type_NGAP_LastVisitedCellInformation_constr_1, CHOICE_constraint },
	asn_MBR_NGAP_LastVisitedCellInformation_1,
	5,	/* Elements count */
	&asn_SPC_NGAP_LastVisitedCellInformation_specs_1	/* Additional specs */
};

