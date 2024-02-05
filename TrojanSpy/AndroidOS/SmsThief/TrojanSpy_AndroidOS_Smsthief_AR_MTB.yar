
rule TrojanSpy_AndroidOS_Smsthief_AR_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Smsthief.AR!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 6c 6c 2f 63 6f 6e 74 61 63 74 64 65 6d 6f } //01 00 
		$a_01_1 = {43 6f 6e 74 61 63 74 42 65 61 6e 7b 74 72 75 65 6e 61 6d 65 3d } //01 00 
		$a_01_2 = {2f 69 6e 64 65 78 2e 70 68 70 2f 41 6a 61 78 2f 67 65 74 5f 63 6f 6e 74 61 63 74 73 } //01 00 
		$a_01_3 = {75 70 4c 6f 61 64 53 4d 53 } //00 00 
	condition:
		any of ($a_*)
 
}