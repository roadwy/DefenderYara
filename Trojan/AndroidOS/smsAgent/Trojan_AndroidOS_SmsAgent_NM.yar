
rule Trojan_AndroidOS_SmsAgent_NM{
	meta:
		description = "Trojan:AndroidOS/SmsAgent.NM,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 45 59 5f 43 48 45 43 4b 5f 53 45 4e 44 5f 4b 45 59 57 4f 52 4b } //2 KEY_CHECK_SEND_KEYWORK
		$a_01_1 = {63 61 74 63 68 5f 63 6f 6e 66 69 72 6d 53 6d 73 } //2 catch_confirmSms
		$a_01_2 = {53 48 4f 57 5f 53 54 41 52 54 5f 53 4d 53 5f 53 45 56 49 43 45 } //2 SHOW_START_SMS_SEVICE
		$a_01_3 = {73 65 74 74 69 6e 67 50 65 72 53 6d 73 } //2 settingPerSms
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}