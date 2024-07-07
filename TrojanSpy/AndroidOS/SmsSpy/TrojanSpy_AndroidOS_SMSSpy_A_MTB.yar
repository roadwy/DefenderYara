
rule TrojanSpy_AndroidOS_SMSSpy_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SMSSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 67 65 74 53 6d 73 53 65 6e 64 2e 70 68 70 } //1 /getSmsSend.php
		$a_00_1 = {73 6d 73 61 70 69 2e 68 65 6a 75 70 61 79 2e 63 6f 6d } //1 smsapi.hejupay.com
		$a_00_2 = {55 70 61 79 53 6d 73 } //1 UpaySms
		$a_00_3 = {53 45 4e 54 5f 53 4d 53 5f 41 43 54 49 4f 4e 5f 55 50 41 59 } //1 SENT_SMS_ACTION_UPAY
		$a_00_4 = {53 65 6e 64 4e 75 6d 62 65 72 5f } //1 SendNumber_
		$a_00_5 = {76 65 72 69 66 79 53 6d 73 52 65 53 65 6e 64 4e 75 6d } //1 verifySmsReSendNum
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}