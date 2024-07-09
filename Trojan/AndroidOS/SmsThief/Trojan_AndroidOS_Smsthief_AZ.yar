
rule Trojan_AndroidOS_SmsThief_AZ{
	meta:
		description = "Trojan:AndroidOS/SmsThief.AZ,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {7a 65 62 72 36 2f 54 68 69 73 41 70 70 6c 69 63 61 74 69 6f 6e } //2 zebr6/ThisApplication
		$a_01_1 = {55 70 6c 6f 61 64 53 6d 73 2e 70 68 70 } //2 UploadSms.php
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_AndroidOS_SmsThief_AZ_2{
	meta:
		description = "Trojan:AndroidOS/SmsThief.AZ,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 6d 73 5f 72 65 63 76 65 } //1 sms_recve
		$a_01_1 = {6d 65 73 73 61 67 65 61 64 64 65 77 73 73 } //1 messageaddewss
		$a_03_2 = {4c 63 6f 6d 2f 68 65 6c 70 64 65 76 [0-14] 73 75 70 70 6f 72 74 2f 72 65 63 65 69 76 65 72 2f 53 6d 73 52 65 63 65 69 76 65 72 } //1
		$a_01_3 = {73 65 6e 64 4e 6f } //1 sendNo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}