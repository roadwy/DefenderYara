
rule TrojanSpy_AndroidOS_Puxis_AS_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Puxis.AS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 72 65 66 5f 61 6c 6c 6f 77 5f 73 6d 73 5f 74 72 61 66 66 69 63 5f 6f 75 74 } //01 00  pref_allow_sms_traffic_out
		$a_03_1 = {63 6f 6d 2e 67 6f 6f 67 6c 65 2e 90 02 12 41 43 43 45 53 53 5f 53 45 43 52 45 54 53 90 00 } //01 00 
		$a_03_2 = {2f 63 6f 6d 2f 67 6f 6f 67 6c 65 90 02 06 70 68 6f 6e 65 6e 75 6d 62 65 72 73 2f 64 61 74 61 2f 50 68 6f 6e 65 4e 75 6d 62 65 72 4d 65 74 61 64 61 74 61 50 72 6f 74 6f 90 00 } //01 00 
		$a_03_3 = {4c 63 6f 6d 2f 67 6f 6f 67 6c 65 90 02 12 42 6c 61 63 6b 41 63 74 69 76 69 74 79 90 00 } //01 00 
		$a_00_4 = {74 72 2f 73 65 72 76 6c 65 74 73 2f 6d 6d 73 } //00 00  tr/servlets/mms
		$a_00_5 = {5d 04 00 } //00 28 
	condition:
		any of ($a_*)
 
}