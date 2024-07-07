
rule Trojan_AndroidOS_SMSfactory_A_MTB{
	meta:
		description = "Trojan:AndroidOS/SMSfactory.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 63 6b 73 53 4d 53 4c 69 73 74 65 6e 65 72 } //1 StacksSMSListener
		$a_01_1 = {73 65 6e 74 53 4d 53 } //1 sentSMS
		$a_01_2 = {61 6e 64 72 6f 69 64 61 70 6b 77 6f 72 6c 64 2e 61 64 73 2e 6d 6f 62 69 6c 65 6c 69 6e 6b 73 } //1 androidapkworld.ads.mobilelinks
		$a_01_3 = {73 6d 73 2e 73 65 72 76 69 63 65 2e 6d 6f 62 69 6c 65 6c 69 6e 6b 73 2e 78 79 7a } //1 sms.service.mobilelinks.xyz
		$a_01_4 = {59 41 4e 44 45 58 5f 53 4d 53 5f 45 56 45 4e 54 } //1 YANDEX_SMS_EVENT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}