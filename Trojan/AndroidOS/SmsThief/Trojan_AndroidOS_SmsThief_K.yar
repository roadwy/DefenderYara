
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
rule Trojan_AndroidOS_SmsThief_K_2{
	meta:
		description = "Trojan:AndroidOS/SmsThief.K,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 64 68 72 75 76 2e 73 6d 73 72 65 63 65 76 69 65 72 } //01 00  com.dhruv.smsrecevier
		$a_01_1 = {2f 6f 6e 6c 69 6e 65 6b 6b 70 61 79 2e 77 69 78 73 69 74 65 2e 63 6f 6d } //01 00  /onlinekkpay.wixsite.com
		$a_01_2 = {64 6f 63 74 6f 72 65 61 70 70 6f 69 6e 6d 65 6e 74 2e 77 69 78 73 69 74 65 2e 63 6f 6d } //01 00  doctoreappoinment.wixsite.com
		$a_01_3 = {63 75 73 74 6f 6d 65 72 61 67 69 73 74 72 61 69 6f 6e 2e 77 69 78 73 69 74 65 2e 63 6f 6d } //00 00  customeragistraion.wixsite.com
	condition:
		any of ($a_*)
 
}