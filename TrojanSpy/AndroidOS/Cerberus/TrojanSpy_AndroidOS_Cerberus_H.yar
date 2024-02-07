
rule TrojanSpy_AndroidOS_Cerberus_H{
	meta:
		description = "TrojanSpy:AndroidOS/Cerberus.H,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {7c 7c 79 6f 75 4e 65 65 64 4d 6f 72 65 52 65 73 6f 75 72 63 65 73 7c 7c } //02 00  ||youNeedMoreResources||
		$a_00_1 = {4c 4f 41 44 49 4e 47 20 49 4e 4a 45 43 54 2b 2b 2b 2b 2b 2b 2b 2b } //01 00  LOADING INJECT++++++++
		$a_00_2 = {73 6d 73 5f 73 64 6b 5f 51 } //01 00  sms_sdk_Q
		$a_00_3 = {72 75 6e 5f 6b 69 6e 67 5f 73 65 72 76 69 63 65 } //01 00  run_king_service
		$a_00_4 = {48 69 64 65 49 6e 6a 65 63 74 } //00 00  HideInject
	condition:
		any of ($a_*)
 
}