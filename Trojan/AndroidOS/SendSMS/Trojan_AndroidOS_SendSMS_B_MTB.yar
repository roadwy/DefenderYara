
rule Trojan_AndroidOS_SendSMS_B_MTB{
	meta:
		description = "Trojan:AndroidOS/SendSMS.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 65 6e 74 5f 73 6d 73 5f 63 6f 75 6e 74 } //01 00  sent_sms_count
		$a_00_1 = {75 72 6c 5f 63 6f 6e 66 69 67 5f 61 75 74 6f 5f 73 6d 73 } //01 00  url_config_auto_sms
		$a_03_2 = {4c 63 6f 6d 2f 68 64 63 90 02 14 53 65 6e 64 53 4d 53 90 00 } //01 00 
		$a_00_3 = {67 65 74 50 61 79 65 64 4c 69 6e 6b } //01 00  getPayedLink
		$a_00_4 = {61 63 74 69 76 61 74 65 2e 70 68 70 } //00 00  activate.php
	condition:
		any of ($a_*)
 
}