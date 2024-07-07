
rule TrojanSpy_AndroidOS_SmsThief_G_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 62 79 6c 2f 73 6d 73 2f 53 6d 53 41 70 70 6c 69 63 61 74 69 6f 6e 3b } //1 com/byl/sms/SmSApplication;
		$a_00_1 = {75 70 6c 6f 61 64 53 6d 53 4d 65 74 68 6f 64 } //1 uploadSmSMethod
		$a_01_2 = {53 4d 53 5f 55 50 } //1 SMS_UP
		$a_00_3 = {2e 63 6f 6d 2f 61 70 69 2f 69 6e 64 65 78 2f 73 6d 73 } //1 .com/api/index/sms
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}