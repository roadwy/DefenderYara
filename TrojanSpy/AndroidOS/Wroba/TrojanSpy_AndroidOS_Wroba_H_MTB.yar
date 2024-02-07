
rule TrojanSpy_AndroidOS_Wroba_H_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Wroba.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 72 79 48 69 64 65 49 63 6f 6e } //01 00  tryHideIcon
		$a_01_1 = {44 65 41 64 6d 69 6e 52 65 63 69 76 65 72 } //01 00  DeAdminReciver
		$a_01_2 = {67 65 74 42 61 6e 6b 42 67 42 79 53 68 6f 72 74 } //01 00  getBankBgByShort
		$a_01_3 = {4d 49 53 53 49 4f 4e 5f 48 49 4a 41 43 4b 5f 42 41 4e 4b } //00 00  MISSION_HIJACK_BANK
	condition:
		any of ($a_*)
 
}