
rule Trojan_AndroidOS_Thamera_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Thamera.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 4d 53 5f 41 50 50 5f 4e 45 57 5f 55 53 45 52 } //1 SMS_APP_NEW_USER
		$a_01_1 = {70 69 64 61 72 61 73 74 2e 72 75 } //1 pidarast.ru
		$a_03_2 = {2f 54 6f 6e 69 90 02 06 2f 74 6f 74 6b 61 2f 6d 61 73 74 65 72 2f 63 6f 6e 66 5f 90 02 04 2e 6a 73 6f 6e 90 00 } //1
		$a_01_3 = {2f 73 6d 73 61 70 70 } //1 /smsapp
		$a_01_4 = {69 6e 73 74 61 6c 6c 65 64 5f 61 70 70 73 5f 6e 61 6d 65 73 } //1 installed_apps_names
		$a_01_5 = {53 4d 53 5f 41 50 50 5f 53 45 4e 44 5f 53 4d 53 5f 53 54 41 54 55 53 } //1 SMS_APP_SEND_SMS_STATUS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}