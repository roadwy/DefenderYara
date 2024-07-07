
rule Backdoor_AndroidOS_Climap_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/Climap.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 6d 73 4d 6f 6e 69 74 6f 72 53 74 61 74 65 } //1 SmsMonitorState
		$a_01_1 = {52 65 63 6f 72 64 4f 70 65 6e 53 74 61 74 65 } //1 RecordOpenState
		$a_01_2 = {55 70 6c 6f 61 64 43 6f 6e 74 61 63 74 52 65 71 75 65 73 74 } //1 UploadContactRequest
		$a_01_3 = {55 70 6c 6f 61 64 52 65 63 6f 72 64 46 69 6c 65 } //1 UploadRecordFile
		$a_01_4 = {74 65 6c 65 70 68 6f 6e 79 2e 64 69 73 61 62 6c 65 2d 63 61 6c 6c } //1 telephony.disable-call
		$a_01_5 = {67 65 6e 65 72 61 74 65 50 61 79 6c 6f 61 64 } //1 generatePayload
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}