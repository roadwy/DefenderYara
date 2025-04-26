
rule Trojan_AndroidOS_SmsSpy_H_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {46 65 65 53 6d 73 53 65 72 76 69 63 65 } //1 FeeSmsService
		$a_01_1 = {44 65 6c 65 74 65 53 74 6f 72 65 53 4d 53 } //1 DeleteStoreSMS
		$a_01_2 = {53 74 61 72 74 53 6d 73 53 65 72 76 69 63 65 } //1 StartSmsService
		$a_01_3 = {73 65 6e 64 5f 73 65 6c 66 5f 73 6d 73 } //1 send_self_sms
		$a_01_4 = {73 74 61 72 74 5f 62 72 6f 77 73 65 72 } //1 start_browser
		$a_01_5 = {73 6d 73 52 65 63 65 69 76 65 72 50 72 6f 63 65 73 73 } //1 smsReceiverProcess
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}