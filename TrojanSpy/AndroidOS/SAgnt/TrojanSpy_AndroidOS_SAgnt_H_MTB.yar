
rule TrojanSpy_AndroidOS_SAgnt_H_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 2e 74 65 6d 70 2f 2e 64 61 74 61 2f 53 4d 53 5f 52 54 } //01 00  /.temp/.data/SMS_RT
		$a_00_1 = {73 65 6e 64 50 68 6f 6e 65 49 6e 66 6f } //01 00  sendPhoneInfo
		$a_00_2 = {72 65 63 5f 69 6e 66 6f } //01 00  rec_info
		$a_00_3 = {41 50 50 53 54 41 54 45 53 45 4e 54 4e 55 4d } //01 00  APPSTATESENTNUM
		$a_00_4 = {64 65 62 75 67 5f 53 4d 53 } //01 00  debug_SMS
		$a_00_5 = {73 65 6e 64 43 75 72 72 65 6e 74 49 6e 66 6f } //01 00  sendCurrentInfo
		$a_00_6 = {2f 2e 74 65 6d 70 2f 4a 6f 62 5f 4c 6f 67 } //00 00  /.temp/Job_Log
	condition:
		any of ($a_*)
 
}