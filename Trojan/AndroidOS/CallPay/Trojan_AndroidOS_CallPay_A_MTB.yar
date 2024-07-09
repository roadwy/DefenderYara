
rule Trojan_AndroidOS_CallPay_A_MTB{
	meta:
		description = "Trojan:AndroidOS/CallPay.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_03_0 = {61 70 70 73 2f [0-13] 2f 64 61 74 61 2f 67 65 6f 69 70 2e 70 68 70 } //1
		$a_03_1 = {61 70 70 73 2f [0-13] 2f 64 61 74 61 2f 67 65 74 46 69 6e 67 65 72 70 72 69 6e 74 49 6e 66 6f 2e 70 68 70 } //1
		$a_01_2 = {70 75 62 6c 69 63 2f 6e 6f 74 69 66 69 63 61 74 69 6f 6e 2f 73 75 62 73 63 72 69 62 65 3f 63 6f 75 6e 74 72 79 } //1 public/notification/subscribe?country
		$a_01_3 = {61 70 70 5f 73 6d 73 5f 72 65 71 75 65 73 74 5f 67 65 74 5f 6e 75 6d 62 65 72 2e 70 68 70 } //1 app_sms_request_get_number.php
		$a_01_4 = {6d 6f 62 6f 70 6f 72 6e 2f 64 61 74 61 2f 64 65 76 69 63 65 5f 61 64 6d 69 6e 2e 70 68 70 } //1 moboporn/data/device_admin.php
		$a_01_5 = {42 65 73 74 47 61 6d 65 73 2f 69 6e 64 65 78 2e 70 68 70 } //1 BestGames/index.php
		$a_01_6 = {68 6f 74 61 70 70 73 78 78 } //1 hotappsxx
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=4
 
}