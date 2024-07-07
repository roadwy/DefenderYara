
rule Trojan_AndroidOS_SmsEye_A_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsEye.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 6d 73 45 79 65 54 6f 6f 6c 73 } //1 SmsEyeTools
		$a_01_1 = {54 65 6c 65 67 72 61 6d 42 6f 74 } //1 TelegramBot
		$a_01_2 = {61 62 79 73 73 61 6c 61 72 6d 79 2f 73 6d 73 65 79 65 } //1 abyssalarmy/smseye
		$a_01_3 = {73 6d 73 45 79 65 44 61 74 61 } //1 smsEyeData
		$a_01_4 = {53 6d 73 45 79 65 57 65 62 76 69 65 77 4b 74 } //1 SmsEyeWebviewKt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}