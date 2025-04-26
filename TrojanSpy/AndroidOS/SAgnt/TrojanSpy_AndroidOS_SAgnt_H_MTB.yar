
rule TrojanSpy_AndroidOS_SAgnt_H_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {2f 2e 74 65 6d 70 2f 2e 64 61 74 61 2f 53 4d 53 5f 52 54 } //1 /.temp/.data/SMS_RT
		$a_00_1 = {73 65 6e 64 50 68 6f 6e 65 49 6e 66 6f } //1 sendPhoneInfo
		$a_00_2 = {72 65 63 5f 69 6e 66 6f } //1 rec_info
		$a_00_3 = {41 50 50 53 54 41 54 45 53 45 4e 54 4e 55 4d } //1 APPSTATESENTNUM
		$a_00_4 = {64 65 62 75 67 5f 53 4d 53 } //1 debug_SMS
		$a_00_5 = {73 65 6e 64 43 75 72 72 65 6e 74 49 6e 66 6f } //1 sendCurrentInfo
		$a_00_6 = {2f 2e 74 65 6d 70 2f 4a 6f 62 5f 4c 6f 67 } //1 /.temp/Job_Log
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}