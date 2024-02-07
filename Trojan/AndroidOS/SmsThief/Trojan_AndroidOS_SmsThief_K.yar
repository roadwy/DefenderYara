
rule Trojan_AndroidOS_SmsThief_K{
	meta:
		description = "Trojan:AndroidOS/SmsThief.K,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {64 61 74 61 2f 69 6e 73 74 61 6c 6c 35 2e 70 68 70 } //02 00  data/install5.php
		$a_00_1 = {45 58 54 52 41 5f 53 4d 53 5f 4e 4f 35 } //02 00  EXTRA_SMS_NO5
		$a_00_2 = {6e 65 77 20 73 6d 73 38 } //02 00  new sms8
		$a_00_3 = {45 58 54 52 41 5f 53 4d 53 5f 4d 45 53 53 41 47 45 35 } //00 00  EXTRA_SMS_MESSAGE5
	condition:
		any of ($a_*)
 
}