
rule Trojan_AndroidOS_SpyC23_A_MTB{
	meta:
		description = "Trojan:AndroidOS/SpyC23.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {21 43 61 6c 6c 52 65 63 6f 72 64 69 6e 67 } //1 !CallRecording
		$a_01_1 = {53 74 55 70 6f 6f 64 53 65 72 76 69 63 65 } //1 StUpoodService
		$a_01_2 = {21 53 6d 73 52 65 63 6f 72 64 69 6e 67 } //1 !SmsRecording
		$a_01_3 = {43 61 6c 6c 5f 48 69 73 74 6f 72 79 5f } //1 Call_History_
		$a_01_4 = {53 4d 53 5f 4b 45 59 5f 47 45 54 5f 44 41 54 41 } //1 SMS_KEY_GET_DATA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}